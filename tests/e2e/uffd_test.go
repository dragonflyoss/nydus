package e2e

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Wire format of the nydus UFFD socket protocol, matching
// nydus/src/uffd/proto.rs.
const (
	// uffdMagic is the magic every frame header starts with.
	uffdMagic = 0x5546_4644

	// uffdMsgStatRequest asks for the device geometry.
	uffdMsgStatRequest = 0x02

	// uffdMsgFetchRequest asks the service to resolve one device range.
	uffdMsgFetchRequest = 0x03

	// uffdMsgProbeRequest asks for the ranges of the whole device.
	uffdMsgProbeRequest = 0x04

	// uffdMsgRangeResponse carries resolved ranges with their backing FDs.
	uffdMsgRangeResponse = 0x81

	// uffdMsgStatResponse carries the device geometry.
	uffdMsgStatResponse = 0x82

	// uffdRangeResponseFlagNext marks a RANGE_RESPONSE frame that another
	// frame of the same response follows.
	uffdRangeResponseFlagNext = 1 << 0

	// uffdHeaderSize is the size of a frame header.
	uffdHeaderSize = 20

	// uffdRangeSize is the encoded size of one range.
	uffdRangeSize = 24

	// uffdStatResponseSize is the payload size of a STAT response.
	uffdStatResponseSize = 16

	// uffdRangeCountSize is the size of the range count that leads a
	// RANGE_RESPONSE payload.
	uffdRangeCountSize = 4

	// uffdFetchRequestSize is the payload size of a FETCH request.
	uffdFetchRequestSize = 16

	// uffdChunkSize is the chunk and block size the images of this
	// suite are built with.
	uffdChunkSize = 4096
)

// TestUffdServiceSmoke drives the stateless STAT, FETCH and PROBE round trips
// against a running `nydus uffd` service and checks the ranges and backing
// descriptors it returns.
func TestUffdServiceSmoke(t *testing.T) {
	requireSubcommand(t, "uffd", "cli,uffd")
	assert := assert.New(t)

	// Build the image and start the service over a local backend.
	workDir := t.TempDir()
	source := filepath.Join(workDir, "corpus")
	bootstrap := filepath.Join(workDir, "image.boot")
	blobDir := filepath.Join(workDir, "blobs")
	cacheDir := filepath.Join(workDir, "cache")
	socketPath := filepath.Join(workDir, "uffd.sock")
	configPath := filepath.Join(workDir, "config.yaml")

	corpus.MakeStandardCorpus(t, source)
	util.BuildImage(t, nydusBin, bootstrap, blobDir, source, uffdChunkSize)
	util.WriteLocalBackendConfig(t, configPath, blobDir, cacheDir, "none")
	startUffdService(t, bootstrap, configPath, socketPath, workDir)

	conn := dialUffdSocket(t, socketPath)
	defer func() { assert.NoError(conn.Close()) }()

	// STAT reports the device geometry.
	deviceSize, blockSize := statUffdDevice(t, conn)
	assert.Greater(deviceSize, uint64(0))
	assert.Equal(uint32(uffdChunkSize), blockSize)

	// FETCH of the first block returns one range starting at the device head.
	sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, uint64(blockSize)))
	fetchRanges, fetchFds, _ := readUffdRangeResponse(t, conn)
	defer closeRawFds(fetchFds)
	if !assert.NotEmpty(fetchRanges) || !assert.Len(fetchFds, len(fetchRanges)) {
		return
	}
	assert.Equal(uint64(0), fetchRanges[0].deviceOffset)
	assert.Equal(uint64(0), fetchRanges[0].fileOffset)
	assert.Equal(uint64(blockSize), fetchRanges[0].length)

	// The first returned FD backs the device head, which is the bootstrap
	// blob: it must carry the EROFS superblock magic at byte offset 1024.
	magic := make([]byte, 4)
	_, err := syscall.Pread(fetchFds[0], magic, int64(fetchRanges[0].fileOffset)+util.ErofsSuperOffset)
	assert.NoError(err)
	assert.Equal(uint32(util.ErofsSuperMagic), binary.LittleEndian.Uint32(magic),
		"FETCH-returned FD must expose the EROFS superblock content")

	// PROBE reports the ranges of the whole device.
	sendUffdRequest(t, conn, uffdMsgProbeRequest, nil)
	probeRanges, probeFds, _ := readUffdRangeResponse(t, conn)
	defer closeRawFds(probeFds)
	assert.NotEmpty(probeRanges)
	assert.Len(probeFds, len(probeRanges))
}

// uffdHeader is the decoded part of a frame header.
type uffdHeader struct {
	// flags are the header flag bits.
	flags uint16

	// msgType is the message type.
	msgType uint16

	// length is the payload length that follows the header.
	length uint32
}

// uffdRange is one resolved device range and where its bytes live.
type uffdRange struct {
	// deviceOffset is the start of the range in the device.
	deviceOffset uint64

	// fileOffset is the start of the range in the backing file.
	fileOffset uint64

	// length is the length of the range in bytes.
	length uint64
}

// startUffdService runs `nydus uffd` on the bootstrap, logging under
// workDir, and waits until its socket accepts connections. The daemon is
// stopped when t ends.
func startUffdService(t *testing.T, bootstrap, configPath, socketPath, workDir string) *util.Daemon {
	t.Helper()
	logDir := filepath.Join(workDir, "logs")
	assert.NoError(t, os.MkdirAll(logDir, 0o755))

	d := &util.Daemon{ConsoleLog: filepath.Join(workDir, "uffd.console.log"), LogDir: logDir}
	d.Start(t, exec.Command(nydusBin, "uffd",
		"--bootstrap", bootstrap,
		"--config", configPath,
		"--socket", socketPath,
		"--log-dir", logDir,
		"--threads", "1",
	))
	t.Cleanup(func() { d.Stop() })

	// Every later step talks to the socket, so a service that never listens
	// stops the test here instead of timing out once per request.
	d.WaitReady(t, func() bool {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})

	return d
}

// dialUffdSocket opens a session on the service socket under the case
// deadline, so a response that never arrives fails the test instead of
// hanging it; a long-lived session extends the deadline per operation.
func dialUffdSocket(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	assert.NoError(t, err)
	assert.NoError(t, conn.SetDeadline(time.Now().Add(uffdCaseDeadline)))

	return conn
}

// statUffdDevice performs a STAT round trip and returns the device size and
// block size.
func statUffdDevice(t *testing.T, conn *net.UnixConn) (uint64, uint32) {
	t.Helper()
	deviceSize, blockSize, err := tryStatUffdDevice(conn)
	assert.NoError(t, err)
	return deviceSize, blockSize
}

// tryStatUffdDevice performs a STAT round trip without testing helpers, so
// the re-executed child can use it too, and returns the device size and
// block size or the first protocol error.
func tryStatUffdDevice(conn *net.UnixConn) (uint64, uint32, error) {
	frame := make([]byte, uffdHeaderSize)
	binary.LittleEndian.PutUint32(frame[0:4], uffdMagic)
	binary.LittleEndian.PutUint16(frame[6:8], uffdMsgStatRequest)
	if _, err := conn.Write(frame); err != nil {
		return 0, 0, fmt.Errorf("send STAT: %w", err)
	}

	header := make([]byte, uffdHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, 0, fmt.Errorf("read STAT response header: %w", err)
	}
	if magic := binary.LittleEndian.Uint32(header[0:4]); magic != uffdMagic {
		return 0, 0, fmt.Errorf("bad response magic %#x", magic)
	}
	if msgType := binary.LittleEndian.Uint16(header[6:8]); msgType != uffdMsgStatResponse {
		return 0, 0, fmt.Errorf("unexpected response type %#x", msgType)
	}
	if payloadLen := binary.LittleEndian.Uint32(header[16:20]); payloadLen != uffdStatResponseSize {
		return 0, 0, fmt.Errorf("unexpected STAT payload length %d", payloadLen)
	}

	payload := make([]byte, uffdStatResponseSize)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, 0, fmt.Errorf("read STAT response payload: %w", err)
	}

	return binary.LittleEndian.Uint64(payload[0:8]), binary.LittleEndian.Uint32(payload[8:12]), nil
}

// sendUffdRequest writes one well-formed request frame of msgType carrying
// payload.
func sendUffdRequest(t *testing.T, conn *net.UnixConn, msgType uint16, payload []byte) {
	t.Helper()
	frame := make([]byte, uffdHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(frame[0:4], uffdMagic)
	binary.LittleEndian.PutUint16(frame[6:8], msgType)
	binary.LittleEndian.PutUint32(frame[16:20], uint32(len(payload)))
	copy(frame[uffdHeaderSize:], payload)

	_, err := conn.Write(frame)
	assert.NoError(t, err)
}

// encodeUffdDeviceRange encodes a FETCH request payload for the device range
// [offset, offset+length).
func encodeUffdDeviceRange(offset, length uint64) []byte {
	payload := make([]byte, uffdFetchRequestSize)
	binary.LittleEndian.PutUint64(payload[0:8], offset)
	binary.LittleEndian.PutUint64(payload[8:16], length)
	return payload
}

// readUffdRangeResponse collects one logical RANGE_RESPONSE (possibly split
// over several NEXT-linked frames) and returns the ranges, the received FDs
// and the number of frames (batches) the response spanned.
func readUffdRangeResponse(t *testing.T, conn *net.UnixConn) ([]uffdRange, []int, int) {
	t.Helper()
	var ranges []uffdRange
	var fds []int
	batches := 0

	for {
		header, payload, frameFds := readUffdFrame(t, conn)
		assert.Equal(t, uint16(uffdMsgRangeResponse), header.msgType)
		frameRanges := decodeUffdRanges(t, payload)
		assert.Len(t, frameFds, len(frameRanges))

		ranges = append(ranges, frameRanges...)
		fds = append(fds, frameFds...)
		batches++

		if header.flags&uffdRangeResponseFlagNext == 0 {
			return ranges, fds, batches
		}
	}
}

// readUffdFrame reads one frame and returns its header, payload and the file
// descriptors passed along with it.
func readUffdFrame(t *testing.T, conn *net.UnixConn) (uffdHeader, []byte, []int) {
	t.Helper()
	buf := make([]byte, 64*1024)
	oob := make([]byte, 4096)
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if !assert.NoError(t, err) || !assert.GreaterOrEqual(t, n, uffdHeaderSize) {
		return uffdHeader{}, nil, nil
	}

	// A payload longer than the first read delivered continues on the stream.
	header := decodeUffdHeader(t, buf[:uffdHeaderSize])
	payloadLen := int(header.length)
	payload := bytes.Clone(buf[uffdHeaderSize:min(n, uffdHeaderSize+payloadLen)])
	if len(payload) < payloadLen {
		extra := make([]byte, payloadLen-len(payload))
		_, err := io.ReadFull(conn, extra)
		assert.NoError(t, err)
		payload = append(payload, extra...)
	}

	return header, payload, parseUnixRights(t, oob[:oobn])
}

// decodeUffdHeader decodes a frame header and checks its magic.
func decodeUffdHeader(t *testing.T, data []byte) uffdHeader {
	t.Helper()
	assert.Len(t, data, uffdHeaderSize)
	assert.Equal(t, uint32(uffdMagic), binary.LittleEndian.Uint32(data[0:4]))
	return uffdHeader{
		flags:   binary.LittleEndian.Uint16(data[4:6]),
		msgType: binary.LittleEndian.Uint16(data[6:8]),
		length:  binary.LittleEndian.Uint32(data[16:20]),
	}
}

// decodeUffdRanges decodes the ranges of one RANGE_RESPONSE payload.
func decodeUffdRanges(t *testing.T, payload []byte) []uffdRange {
	t.Helper()
	if !assert.GreaterOrEqual(t, len(payload), uffdRangeCountSize) {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(payload[0:4]))
	if !assert.Len(t, payload, uffdRangeCountSize+count*uffdRangeSize) {
		return nil
	}

	ranges := make([]uffdRange, 0, count)
	for offset := uffdRangeCountSize; offset < len(payload); offset += uffdRangeSize {
		ranges = append(ranges, uffdRange{
			deviceOffset: binary.LittleEndian.Uint64(payload[offset : offset+8]),
			fileOffset:   binary.LittleEndian.Uint64(payload[offset+8 : offset+16]),
			length:       binary.LittleEndian.Uint64(payload[offset+16 : offset+24]),
		})
	}

	return ranges
}

// parseUnixRights returns the file descriptors carried in the SCM_RIGHTS
// control messages of oob.
func parseUnixRights(t *testing.T, oob []byte) []int {
	t.Helper()
	if len(oob) == 0 {
		return nil
	}

	messages, err := syscall.ParseSocketControlMessage(oob)
	assert.NoError(t, err)

	var fds []int
	for _, message := range messages {
		rights, err := syscall.ParseUnixRights(&message)
		assert.NoError(t, err)
		fds = append(fds, rights...)
	}

	return fds
}

// closeRawFds closes every descriptor received over the socket.
func closeRawFds(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

// HANDSHAKE protocol constants and suite deadlines, matching
// nydus/src/uffd/proto.rs.
const (
	// uffdMsgHandshake registers a userfaultfd and its VMA regions.
	uffdMsgHandshake = 0x01

	// uffdProtocolVersion is the protocol version the handshake declares.
	uffdProtocolVersion = 1

	// uffdHandshakeFlagCopy selects managed UFFDIO_COPY completion; without it
	// the service answers faults with RANGE_RESPONSE frames (zerocopy).
	uffdHandshakeFlagCopy = 0x01

	// uffdHandshakeFlagPrefault asks the service to resolve the whole region
	// right after the handshake.
	uffdHandshakeFlagPrefault = 0x02

	// uffdRegionSize is the encoded size of one VMA region.
	uffdRegionSize = 40

	// uffdMaxRangesPerMsg is the most ranges one RANGE_RESPONSE frame carries.
	uffdMaxRangesPerMsg = 16

	// uffdFaultDeadline bounds a single fault.
	uffdFaultDeadline = 10 * time.Second

	// uffdCaseDeadline bounds any failing case.
	uffdCaseDeadline = 30 * time.Second
)

// Linux userfaultfd ABI, matching nydus/src/uffd/core.rs.
const (
	// uffdioAPIIoctl is UFFDIO_API.
	uffdioAPIIoctl = 0xc018aa3f

	// uffdioRegisterIoctl is UFFDIO_REGISTER.
	uffdioRegisterIoctl = 0xc020aa00

	// uffdioWakeIoctl is UFFDIO_WAKE.
	uffdioWakeIoctl = 0x8010aa02

	// uffdAPIVersion is the UFFD_API version requested in UFFDIO_API.
	uffdAPIVersion = 0xAA

	// uffdRegisterMissing is UFFDIO_REGISTER_MODE_MISSING.
	uffdRegisterMissing = 0x1

	// uffdioBitWake is the _UFFDIO_WAKE bit of uffdio_register.ioctls.
	uffdioBitWake = 1 << 0x02

	// uffdioBitCopy is the _UFFDIO_COPY bit of uffdio_register.ioctls.
	uffdioBitCopy = 1 << 0x03

	// uffdioBitZeropage is the _UFFDIO_ZEROPAGE bit of uffdio_register.ioctls.
	uffdioBitZeropage = 1 << 0x04

	// uffdioBitsRequired are the ioctls every registered VMA must support.
	uffdioBitsRequired = uffdioBitWake | uffdioBitCopy | uffdioBitZeropage
)

// Child-process helper environment, used by the outstanding-fault lifecycle
// case: an unresolved userfaultfd fault blocks its thread inside the kernel
// and starves the Go runtime's timers in that process, so the outstanding
// fault must live in a child process the test can observe and tear down from
// outside.
const (
	// uffdChildModeEnv selects the child helper when the test binary re-execs.
	uffdChildModeEnv = "NYDUS_E2E_UFFD_CHILD_MODE"

	// uffdChildModeOutstandingFault is the child mode that leaves one fault
	// outstanding.
	uffdChildModeOutstandingFault = "outstanding-fault"

	// uffdChildSocketEnv passes the service socket path to the child.
	uffdChildSocketEnv = "NYDUS_E2E_UFFD_CHILD_SOCKET"

	// uffdChildDeviceSizeEnv passes the device size to the child.
	uffdChildDeviceSizeEnv = "NYDUS_E2E_UFFD_CHILD_DEVICE_SIZE"

	// uffdChildBlockSizeEnv passes the block size to the child.
	uffdChildBlockSizeEnv = "NYDUS_E2E_UFFD_CHILD_BLOCK_SIZE"

	// uffdChildRegionSizeEnv passes the declared region size to the child.
	uffdChildRegionSizeEnv = "NYDUS_E2E_UFFD_CHILD_REGION_SIZE"
)

// uffdioAPIArg is struct uffdio_api.
type uffdioAPIArg struct {
	// api is the requested, then granted, API version.
	api uint64

	// features are the requested, then granted, feature bits.
	features uint64

	// ioctls are the ioctls the kernel supports on this userfaultfd.
	ioctls uint64
}

// uffdioRangeArg is struct uffdio_range.
type uffdioRangeArg struct {
	// start is the first virtual address of the range.
	start uint64

	// len is the length of the range in bytes.
	len uint64
}

// uffdioRegisterArg is struct uffdio_register.
type uffdioRegisterArg struct {
	// rangeArg is the range to register.
	rangeArg uffdioRangeArg

	// mode is the UFFDIO_REGISTER_MODE_* bits.
	mode uint64

	// ioctls are the ioctls the kernel supports on the registered range.
	ioctls uint64
}

// uffdVmaRegion is one VMA region declared in the HANDSHAKE.
type uffdVmaRegion struct {
	// virtAddr is the first virtual address of the region.
	virtAddr uint64

	// size is the length of the region in bytes.
	size uint64

	// offset is the device offset the region starts at.
	offset uint64

	// faultSize is the number of bytes the service resolves per fault.
	faultSize uint64

	// prot are the mmap protection bits of the region.
	prot int32

	// flags are the mmap flags of the region.
	flags int32
}

// uffdIoctl issues the ioctl req on fd with arg and returns the errno as an
// error.
func uffdIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}

	return nil
}

// probeUffdCapability explicitly checks every userfaultfd capability the
// suite depends on: the syscall itself, the UFFDIO_API handshake, MISSING-mode
// registration and the UFFDIO_COPY/ZEROPAGE/WAKE ioctls.
func probeUffdCapability() error {
	rawFd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
	if errno != 0 {
		return fmt.Errorf("userfaultfd syscall unavailable: %v (check vm.unprivileged_userfaultfd or run as root)", errno)
	}
	fd := int(rawFd)
	defer func() { _ = unix.Close(fd) }()

	api := uffdioAPIArg{api: uffdAPIVersion}
	if err := uffdIoctl(fd, uffdioAPIIoctl, unsafe.Pointer(&api)); err != nil {
		return fmt.Errorf("UFFDIO_API handshake failed: %v", err)
	}

	// Register one anonymous page to learn which ioctls the kernel grants.
	pageSize := unix.Getpagesize()
	vma, err := unix.Mmap(-1, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("anonymous mmap failed: %v", err)
	}
	defer func() { _ = unix.Munmap(vma) }()

	register := uffdioRegisterArg{
		rangeArg: uffdioRangeArg{start: uint64(uintptr(unsafe.Pointer(&vma[0]))), len: uint64(pageSize)},
		mode:     uffdRegisterMissing,
	}
	if err := uffdIoctl(fd, uffdioRegisterIoctl, unsafe.Pointer(&register)); err != nil {
		return fmt.Errorf("UFFDIO_REGISTER (MISSING mode) failed: %v", err)
	}
	if register.ioctls&uffdioBitsRequired != uffdioBitsRequired {
		return fmt.Errorf("required UFFD ioctls missing: have %#x, need WAKE|COPY|ZEROPAGE (%#x)", register.ioctls, uint64(uffdioBitsRequired))
	}

	return nil
}

// isUffdRequired reports whether a missing runner capability must fail the
// suite instead of skipping it. CI sets NYDUS_E2E_UFFD_REQUIRE=1 so the gate
// can never be silently skipped.
func isUffdRequired() bool {
	return os.Getenv("NYDUS_E2E_UFFD_REQUIRE") != ""
}

// skipUnlessRequired skips the test with the formatted reason, or fails it
// when NYDUS_E2E_UFFD_REQUIRE forbids skipping.
func skipUnlessRequired(t *testing.T, format string, args ...any) {
	t.Helper()
	if isUffdRequired() {
		t.Fatalf("unsupported-runner: "+format+" (NYDUS_E2E_UFFD_REQUIRE forbids skipping)", args...)
	}
	t.Skipf(format+" (set NYDUS_E2E_UFFD_REQUIRE=1 to fail instead)", args...)
}

// requireUffdRunner skips the test, or fails it under NYDUS_E2E_UFFD_REQUIRE,
// when the runner lacks userfaultfd support.
func requireUffdRunner(t *testing.T) {
	t.Helper()
	if err := probeUffdCapability(); err != nil {
		skipUnlessRequired(t, "runner lacks userfaultfd capability: %v", err)
	}
}

// requireSubcommand skips the test, or fails it under NYDUS_E2E_UFFD_REQUIRE,
// when the nydus binary was built without subcommand, naming the cargo
// features that add it.
func requireSubcommand(t *testing.T, subcommand, features string) {
	t.Helper()
	if out, err := exec.Command(nydusBin, subcommand, "--help").CombinedOutput(); err != nil {
		skipUnlessRequired(t, "nydus binary lacks the %s subcommand; build with --features %s: %s", subcommand, features, out)
	}
}

// TestUffdCapabilityPreflight is the explicit runner preflight: it verifies
// the userfaultfd syscall, the UFFDIO_API handshake, MISSING-mode
// registration and the required ioctls before any integration case runs. With
// NYDUS_E2E_UFFD_REQUIRE set it fails closed instead of skipping.
func TestUffdCapabilityPreflight(t *testing.T) {
	// Log the runner facts a capability failure is usually explained by.
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		t.Logf("runner kernel: %s %s", unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Version[:]))
	}
	if data, err := os.ReadFile("/proc/sys/vm/unprivileged_userfaultfd"); err == nil {
		t.Logf("vm.unprivileged_userfaultfd=%s euid=%d", strings.TrimSpace(string(data)), os.Geteuid())
	}

	requireUffdRunner(t)
	t.Log("userfaultfd syscall, UFFDIO_API, MISSING-mode REGISTER and WAKE/COPY/ZEROPAGE ioctls all available")
}

// uffdFixture is one nydus image plus a running `nydus uffd` service.
type uffdFixture struct {
	// workDir is the per-test scratch directory everything below lives in.
	workDir string

	// source is the source tree the image was built from.
	source string

	// bootstrap is the image bootstrap the service serves.
	bootstrap string

	// blobDir is the local backend directory holding the blobs.
	blobDir string

	// cacheDir is the chunk cache directory of the service.
	cacheDir string

	// socketPath is the Unix socket the service listens on.
	socketPath string

	// configPath is the nydus config of the local backend.
	configPath string

	// fullBlobs are the blobs the build produced, one per layer.
	fullBlobs []string

	// service is the running service, nil before start.
	service *util.Daemon
}

// uffdFixtureOptions configures newUffdFixture.
type uffdFixtureOptions struct {
	// blobCount > 1 builds a merged multi-blob image (one blob per layer) so
	// FETCH/PROBE/prefault produce more than uffdMaxRangesPerMsg ranges and
	// force multi-batch RANGE_RESPONSE framing.
	blobCount int

	// beforeStart mutates the fixture (e.g. corrupts backend blobs) after the
	// image is built but before the service starts.
	beforeStart func(t *testing.T, fixture *uffdFixture)
}

// newUffdFixture builds the image, writes the local backend config and
// starts the service, skipping when the binary lacks the uffd subcommand.
func newUffdFixture(t *testing.T, options uffdFixtureOptions) *uffdFixture {
	t.Helper()
	requireSubcommand(t, "uffd", "cli,uffd")

	workDir := t.TempDir()
	fixture := &uffdFixture{
		workDir:    workDir,
		source:     filepath.Join(workDir, "corpus"),
		bootstrap:  filepath.Join(workDir, "image.boot"),
		blobDir:    filepath.Join(workDir, "blobs"),
		cacheDir:   filepath.Join(workDir, "cache"),
		socketPath: filepath.Join(workDir, "uffd.sock"),
		configPath: filepath.Join(workDir, "config.yaml"),
	}
	registerUffdEvidence(t, fixture)

	// Build one image from the standard corpus, or merge one blob per layer.
	// `nydus merge` derives each layer's blob ID from its sha256-hex file
	// name, so the merge sources are the blob files themselves (each carries
	// its embedded bootstrap), not separate .boot files.
	if options.blobCount <= 1 {
		corpus.MakeStandardCorpus(t, fixture.source)
		fixture.fullBlobs = append(fixture.fullBlobs,
			util.BuildImage(t, nydusBin, fixture.bootstrap, fixture.blobDir, fixture.source, uffdChunkSize))
	} else {
		for i := range options.blobCount {
			layerDir := filepath.Join(workDir, fmt.Sprintf("layer-%02d", i))
			layer := corpus.NewCorpus(t, layerDir)
			data := bytes.Repeat([]byte{byte(i + 1)}, 8192+i*512)
			layer.CreateFile(t, fmt.Sprintf("layer-%02d.bin", i), data)
			fixture.fullBlobs = append(fixture.fullBlobs,
				util.BuildImage(t, nydusBin, "", fixture.blobDir, layerDir, uffdChunkSize))
		}
		util.MergeBootstrap(t, nydusBin, fixture.bootstrap, fixture.fullBlobs...)
	}
	util.WriteLocalBackendConfig(t, fixture.configPath, fixture.blobDir, fixture.cacheDir, "none")

	if options.beforeStart != nil {
		options.beforeStart(t, fixture)
	}
	fixture.start(t)

	return fixture
}

// start runs the service; it is stopped when t ends.
func (f *uffdFixture) start(t *testing.T) {
	t.Helper()
	f.service = startUffdService(t, f.bootstrap, f.configPath, f.socketPath, f.workDir)
}

// registerUffdEvidence writes structured failure evidence into
// NYDUS_E2E_UFFD_EVIDENCE_DIR when the test fails: case ID, commit, runner
// kernel, capability state, service liveness, FD summary and the service
// logs.
func registerUffdEvidence(t *testing.T, fixture *uffdFixture) {
	t.Helper()
	evidenceDir := os.Getenv("NYDUS_E2E_UFFD_EVIDENCE_DIR")
	if evidenceDir == "" {
		return
	}

	caseID := t.Name()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}

		caseDir := filepath.Join(evidenceDir, strings.ReplaceAll(caseID, "/", "_"))
		if err := os.MkdirAll(caseDir, 0o755); err != nil {
			t.Logf("evidence: cannot create %s: %v", caseDir, err)
			return
		}

		// Collect the runner and service state into the metadata.
		meta := map[string]any{
			"case":       caseID,
			"commit":     os.Getenv("GITHUB_SHA"),
			"goos":       runtime.GOOS,
			"goarch":     runtime.GOARCH,
			"time":       time.Now().UTC().Format(time.RFC3339),
			"capability": "ok",
		}
		if err := probeUffdCapability(); err != nil {
			meta["capability"] = err.Error()
		}
		var uts unix.Utsname
		if err := unix.Uname(&uts); err == nil {
			meta["kernel_release"] = unix.ByteSliceToString(uts.Release[:])
			meta["kernel_version"] = unix.ByteSliceToString(uts.Version[:])
		}
		if fds, err := os.ReadDir("/proc/self/fd"); err == nil {
			meta["open_fds"] = len(fds)
		}
		if service := fixture.service; service != nil {
			meta["service_alive"] = service.Alive()
			_ = os.WriteFile(filepath.Join(caseDir, "service.log"), []byte(service.Logs()), 0o644)
		}

		// Write the metadata.
		if encoded, err := json.MarshalIndent(meta, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(caseDir, "meta.json"), encoded, 0o644)
		}

		t.Logf("evidence written to %s", caseDir)
	})
}

// fetchUffdDeviceBytes assembles the expected device bytes for
// [offset, offset+length) through a dedicated FETCH connection: data ranges
// are pread from the returned backing FDs, /dev/zero ranges and everything
// past a backing file's EOF read as zero. This is the reference the
// fault-populated memory is compared against.
func fetchUffdDeviceBytes(t *testing.T, socketPath string, offset, length uint64) []byte {
	t.Helper()
	conn := dialUffdSocket(t, socketPath)
	defer func() { assert.NoError(t, conn.Close()) }()

	sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(offset, length))
	ranges, fds, _ := readUffdRangeResponse(t, conn)
	defer closeRawFds(fds)

	// Zero ranges leave their window untouched, data ranges fill it from the
	// backing file.
	buf := make([]byte, length)
	if !assert.Len(t, fds, len(ranges)) {
		return buf
	}
	for i, r := range ranges {
		if !assert.GreaterOrEqual(t, r.deviceOffset, offset, "range before requested window") ||
			!assert.LessOrEqual(t, r.deviceOffset+r.length, offset+length, "range beyond requested window") {
			return buf
		}
		if util.IsCharDevice(t, fds[i]) {
			continue
		}
		dst := buf[r.deviceOffset-offset : r.deviceOffset-offset+r.length]

		// Fill the range with pread; bytes past EOF stay zero, matching the
		// sparse device semantics.
		for total := 0; total < len(dst); {
			n, err := unix.Pread(fds[i], dst[total:], int64(r.fileOffset)+int64(total))
			if !assert.NoError(t, err, "pread fd %d at %d", fds[i], int64(r.fileOffset)+int64(total)) || n == 0 {
				break
			}
			total += n
		}
	}

	return buf
}

// uffdFaultClient owns one anonymous VMA registered with a real userfaultfd
// whose fd has been handed to the nydus UFFD service via HANDSHAKE.
type uffdFaultClient struct {
	// conn is the session the userfaultfd was handed over on.
	conn *net.UnixConn

	// uffd is the client's copy of the userfaultfd.
	uffd int

	// vma is the anonymous VMA covering the device.
	vma []byte

	// deviceSize is the device size STAT reported.
	deviceSize uint64

	// blockSize is the block size STAT reported.
	blockSize uint32

	// faultSize is the number of bytes the service resolves per fault.
	faultSize uint64

	// region is the VMA region declared in the HANDSHAKE.
	region uffdVmaRegion

	// touchers counts the goroutines that may be blocked in a fault.
	touchers sync.WaitGroup

	// closeOnce makes close idempotent.
	closeOnce sync.Once
}

// newUffdFaultClient maps an anonymous VMA covering the device, creates and
// registers a real userfaultfd, and performs the HANDSHAKE. regionSize == 0
// registers the full device; a smaller value registers only a prefix so
// faults outside it stay deliberately unresolved (lifecycle tests).
func newUffdFaultClient(t *testing.T, fixture *uffdFixture, handshakeFlags byte, faultSize, regionSize uint64) *uffdFaultClient {
	t.Helper()
	conn := dialUffdSocket(t, fixture.socketPath)
	deviceSize, blockSize := statUffdDevice(t, conn)
	assert.Greater(t, deviceSize, uint64(0))

	// Every later step indexes the VMA, so a failed mmap stops the test.
	vma, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if !assert.NoError(t, err, "anonymous VMA mmap") {
		t.FailNow()
	}

	// Register the VMA in MISSING mode with a fresh userfaultfd.
	rawFd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
	assert.Zero(t, errno, "userfaultfd syscall")
	uffd := int(rawFd)
	api := uffdioAPIArg{api: uffdAPIVersion}
	assert.NoError(t, uffdIoctl(uffd, uffdioAPIIoctl, unsafe.Pointer(&api)), "UFFDIO_API")

	base := uint64(uintptr(unsafe.Pointer(&vma[0])))
	register := uffdioRegisterArg{
		rangeArg: uffdioRangeArg{start: base, len: deviceSize},
		mode:     uffdRegisterMissing,
	}
	assert.NoError(t, uffdIoctl(uffd, uffdioRegisterIoctl, unsafe.Pointer(&register)), "UFFDIO_REGISTER")
	assert.Equal(t, uint64(uffdioBitsRequired), register.ioctls&uffdioBitsRequired, "kernel must support WAKE/COPY/ZEROPAGE for the registered VMA")

	if regionSize == 0 {
		regionSize = deviceSize
	}

	c := &uffdFaultClient{
		conn:       conn,
		uffd:       uffd,
		vma:        vma,
		deviceSize: deviceSize,
		blockSize:  blockSize,
		faultSize:  faultSize,
		region: uffdVmaRegion{
			virtAddr:  base,
			size:      regionSize,
			offset:    0,
			faultSize: faultSize,
			prot:      int32(unix.PROT_READ | unix.PROT_WRITE),
			flags:     int32(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
		},
	}

	// Hand the userfaultfd to the service along with the region.
	frame := encodeUffdHandshakeFrame(uffdProtocolVersion, handshakeFlags, []uffdVmaRegion{c.region})
	n, oobn, err := conn.WriteMsgUnix(frame, unix.UnixRights(uffd), nil)
	assert.NoError(t, err, "HANDSHAKE send")
	assert.Equal(t, len(frame), n)
	assert.Equal(t, len(unix.UnixRights(uffd)), oobn)

	t.Cleanup(func() { c.close(t) })

	return c
}

// close tears the client down in an order that can never SIGSEGV or hang the
// test binary: drop the socket so the service releases its
// userfaultfd copy, close our copy so pending faults resolve as anonymous
// zero pages, join every toucher under a deadline, then unmap the VMA.
func (c *uffdFaultClient) close(t *testing.T) {
	t.Helper()
	c.closeOnce.Do(func() {
		_ = c.conn.Close()
		_ = unix.Close(c.uffd)

		done := make(chan struct{})
		go func() {
			c.touchers.Wait()
			close(done)
		}()

		// A blocked toucher would fault on the unmapped VMA; leak the mapping
		// instead of crashing and report the stuck fault.
		select {
		case <-done:
			assert.NoError(t, unix.Munmap(c.vma))
		case <-time.After(uffdCaseDeadline):
			t.Errorf("toucher goroutines still blocked %v after closing every userfaultfd; leaking VMA", uffdCaseDeadline)
		}
	})
}

// assertHandshakeAccepted proves the HANDSHAKE was accepted: a rejected
// handshake terminates the connection so the STAT round trip below would fail.
func (c *uffdFaultClient) assertHandshakeAccepted(t *testing.T) {
	t.Helper()
	assert.NoError(t, c.conn.SetDeadline(time.Now().Add(uffdCaseDeadline)))
	size, _ := statUffdDevice(t, c.conn)
	assert.Equal(t, c.deviceSize, size)
}

// uffdTouch is the outcome of one asynchronous read of the VMA.
type uffdTouch struct {
	// data are the bytes the read resolved to.
	data []byte

	// err is the process_vm_readv failure, if any.
	err error
}

// touchAsync faults vma[offset, offset+length) in on a separate goroutine and
// delivers the resolved bytes on the channel. The touch reads them through
// process_vm_readv(2) on the own process instead of a direct load: the kernel
// resolves the missing page through the same userfaultfd path, but the Go
// runtime sees the goroutine blocked in a syscall, so a concurrent
// stop-the-world (e.g. a GC triggered by an allocation elsewhere in the test)
// completes while the fault is outstanding. A direct load would wedge the OS
// thread at a non-preemptible page fault, and any stop-the-world would then
// deadlock the tests that serve their own faults in-process (zerocopy): the
// serving goroutine blocks in gcStart waiting for the faulting thread, which
// only resumes once the fault it is waiting on gets served.
func (c *uffdFaultClient) touchAsync(offset, length uint64) <-chan uffdTouch {
	ch := make(chan uffdTouch, 1)
	c.touchers.Add(1)
	go func() {
		defer c.touchers.Done()
		data := make([]byte, length)
		for total := uint64(0); total < length; {
			local := []unix.Iovec{{Base: &data[total], Len: length - total}}
			remote := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&c.vma[offset+total])), Len: int(length - total)}}
			n, err := unix.ProcessVMReadv(os.Getpid(), local, remote, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil || n == 0 {
				ch <- uffdTouch{err: fmt.Errorf("process_vm_readv touch at device offset %#x: n=%d err=%v", offset+total, n, err)}
				return
			}
			total += uint64(n)
		}

		ch <- uffdTouch{data: data}
	}()

	return ch
}

// waitUffdTouch returns the bytes a touch resolved to, failing the test when
// the touch errors or the fault does not complete within timeout.
func waitUffdTouch(t *testing.T, ch <-chan uffdTouch, timeout time.Duration, desc string) []byte {
	t.Helper()
	select {
	case touch := <-ch:
		if !assert.NoError(t, touch.err, desc) {
			t.FailNow()
		}
		return touch.data
	case <-time.After(timeout):
		t.Fatalf("page fault did not complete within %v: %s", timeout, desc)
		return nil
	}
}

// serveOneZerocopyFault reads the RANGE_RESPONSE batches for one fault,
// installs fixed mappings from the returned FDs, wakes the fault range on the
// client-held userfaultfd and closes the received FDs. It returns the ranges
// and the number of RANGE_RESPONSE batches.
func (c *uffdFaultClient) serveOneZerocopyFault(t *testing.T) ([]uffdRange, int) {
	t.Helper()
	ranges, fds, batches := c.readRangeBatches(t, uffdFaultDeadline)
	c.mapRanges(t, ranges, fds, true)
	closeRawFds(fds)
	return ranges, batches
}

// readRangeBatches reads one logical RANGE_RESPONSE under a deadline.
func (c *uffdFaultClient) readRangeBatches(t *testing.T, timeout time.Duration) ([]uffdRange, []int, int) {
	t.Helper()
	assert.NoError(t, c.conn.SetReadDeadline(time.Now().Add(timeout)))
	return readUffdRangeResponse(t, c.conn)
}

// mapRanges installs the returned ranges over the anonymous VMA with
// MAP_FIXED: data ranges map the backing FD read-only, /dev/zero ranges map
// fresh anonymous zero pages. When wake is set, the covered window is woken
// with UFFDIO_WAKE afterwards.
func (c *uffdFaultClient) mapRanges(t *testing.T, ranges []uffdRange, fds []int, wake bool) {
	t.Helper()
	if !assert.NotEmpty(t, ranges, "fault resolution returned no ranges") ||
		!assert.Len(t, fds, len(ranges), "SCM_RIGHTS FD count must match range count") {
		return
	}

	// Map every range and track the virtual window they cover.
	pageSize := uint64(unix.Getpagesize())
	lo, hi := ^uint64(0), uint64(0)
	for i, r := range ranges {
		if !assert.GreaterOrEqual(t, r.deviceOffset, c.region.offset, "range below registered region") ||
			!assert.LessOrEqual(t, r.deviceOffset+r.length, c.region.offset+c.region.size, "range beyond registered region") {
			return
		}
		delta := r.deviceOffset - c.region.offset
		virtStart := c.region.virtAddr + delta
		lo = min(lo, virtStart)
		hi = max(hi, virtStart+r.length)

		// Zero holes start after (possibly unaligned) data tails whose partial
		// page already reads as zero past the backing file EOF, so only the
		// page-aligned part needs a fresh anonymous mapping.
		if util.IsCharDevice(t, fds[i]) {
			zeroStart := util.AlignUp(delta, pageSize)
			zeroEnd := util.AlignUp(delta+r.length, pageSize)
			if zeroStart < zeroEnd {
				addr := unsafe.Add(unsafe.Pointer(&c.vma[0]), int(zeroStart))
				_, err := unix.MmapPtr(-1, 0, addr, uintptr(zeroEnd-zeroStart),
					unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED)
				assert.NoError(t, err, "MAP_FIXED zero range at device offset %#x", r.deviceOffset)
			}
			continue
		}

		assert.Zero(t, delta%pageSize, "data range device offset must be page aligned")
		assert.Zero(t, r.fileOffset%pageSize, "data range file offset must be page aligned")
		addr := unsafe.Add(unsafe.Pointer(&c.vma[0]), int(delta))
		_, err := unix.MmapPtr(fds[i], int64(r.fileOffset), addr, uintptr(r.length),
			unix.PROT_READ, unix.MAP_PRIVATE|unix.MAP_FIXED)
		assert.NoError(t, err, "MAP_FIXED data range at device offset %#x", r.deviceOffset)
	}

	if wake {
		start := util.AlignDown(lo, pageSize)
		arg := uffdioRangeArg{start: start, len: util.AlignUp(hi, pageSize) - start}
		assert.NoError(t, uffdIoctl(c.uffd, uffdioWakeIoctl, unsafe.Pointer(&arg)), "UFFDIO_WAKE")
	}
}

// encodeUffdHandshakeFrame encodes a HANDSHAKE frame declaring regions.
func encodeUffdHandshakeFrame(version uint16, flags byte, regions []uffdVmaRegion) []byte {
	payloadLen := 4 + len(regions)*uffdRegionSize
	frame := make([]byte, uffdHeaderSize+payloadLen)
	binary.LittleEndian.PutUint32(frame[0:4], uffdMagic)
	binary.LittleEndian.PutUint16(frame[6:8], uffdMsgHandshake)
	binary.LittleEndian.PutUint32(frame[16:20], uint32(payloadLen))
	binary.LittleEndian.PutUint16(frame[20:22], version)
	frame[22] = flags
	frame[23] = byte(len(regions))

	offset := 24
	for _, r := range regions {
		binary.LittleEndian.PutUint64(frame[offset:offset+8], r.virtAddr)
		binary.LittleEndian.PutUint64(frame[offset+8:offset+16], r.size)
		binary.LittleEndian.PutUint64(frame[offset+16:offset+24], r.offset)
		binary.LittleEndian.PutUint64(frame[offset+24:offset+32], r.faultSize)
		binary.LittleEndian.PutUint32(frame[offset+32:offset+36], uint32(r.prot))
		binary.LittleEndian.PutUint32(frame[offset+36:offset+40], uint32(r.flags))
		offset += uffdRegionSize
	}

	return frame
}

// TestUffdRealFaultCopy verifies managed-copy fault completion: a real
// userfaultfd plus anonymous
// VMA is handed to the service, cold reads block until the service resolves
// them with UFFDIO_COPY/UFFDIO_ZEROPAGE, and the populated memory is compared
// byte-for-byte against the device reference, the EROFS superblock and, when
// the runner supports it, a loop-mounted EROFS whole-tree diff against the
// source corpus.
func TestUffdRealFaultCopy(t *testing.T) {
	requireUffdRunner(t)
	assert := assert.New(t)
	fixture := newUffdFixture(t, uffdFixtureOptions{})
	client := newUffdFaultClient(t, fixture, uffdHandshakeFlagCopy, 2*1024*1024, 0)
	client.assertHandshakeAccepted(t)

	expected := fetchUffdDeviceBytes(t, fixture.socketPath, 0, client.deviceSize)
	assert.Equal(uint32(util.ErofsSuperMagic), binary.LittleEndian.Uint32(expected[util.ErofsSuperOffset:util.ErofsSuperOffset+4]),
		"device reference must carry the EROFS superblock magic")

	// Cold: the very first fault must complete within the single-fault
	// deadline and return the right byte.
	first := waitUffdTouch(t, client.touchAsync(0, 1), uffdFaultDeadline, "cold fault at device offset 0")
	assert.Equal(expected[0], first[0], "cold fault returned a wrong byte")

	// Touch every fault window under an explicit per-fault deadline, then
	// snapshot the whole device.
	for offset := uint64(0); offset < client.deviceSize; offset += client.faultSize {
		waitUffdTouch(t, client.touchAsync(offset, 1), uffdFaultDeadline, fmt.Sprintf("cold fault at device offset %#x", offset))
	}
	cold := waitUffdTouch(t, client.touchAsync(0, client.deviceSize), uffdCaseDeadline, "cold full-device read")
	util.CheckBytesEqual(t, expected, cold, "cold fault-populated memory vs device reference")
	assert.Equal(uint32(util.ErofsSuperMagic), binary.LittleEndian.Uint32(cold[util.ErofsSuperOffset:util.ErofsSuperOffset+4]),
		"fault-populated memory must carry the EROFS superblock magic")

	// The device tail past the flattened data must read as zero pages.
	tail := cold[client.deviceSize-uint64(client.blockSize):]
	assert.Equal(make([]byte, client.blockSize), tail, "device tail must be zero-filled")

	// Warm: repeated reads of the already-resolved pages must be identical
	// and must not need the service.
	warm := waitUffdTouch(t, client.touchAsync(0, client.deviceSize), uffdCaseDeadline, "warm full-device read")
	util.CheckBytesEqual(t, expected, warm, "warm repeated read vs device reference")

	// Corpus-level ground truth: the fault-populated memory is a complete
	// EROFS image; loop-mount it and diff the tree against the source corpus.
	if os.Geteuid() != 0 || !util.ErofsSupported() {
		t.Log("skipping loop-mounted EROFS corpus diff (requires root and EROFS kernel support)")
		return
	}
	imagePath := filepath.Join(fixture.workDir, "faulted-device.img")
	assert.NoError(os.WriteFile(imagePath, cold, 0o644))
	util.CheckDirectoryEqual(t, fixture.source, util.MountErofsLoop(t, imagePath), true)
}

// TestUffdRealFaultZeropage verifies that a fault in a /dev/zero-backed hole
// (the device tail) completes through the managed zero-page path and reads as
// zeros.
func TestUffdRealFaultZeropage(t *testing.T) {
	requireUffdRunner(t)
	assert := assert.New(t)
	fixture := newUffdFixture(t, uffdFixtureOptions{})
	client := newUffdFaultClient(t, fixture, uffdHandshakeFlagCopy, uint64(uffdChunkSize), 0)
	client.assertHandshakeAccepted(t)

	// Locate the tail hole: the last resolved range of the device must be
	// backed by /dev/zero (flattened data is aligned up to the device size).
	conn := dialUffdSocket(t, fixture.socketPath)
	defer func() { assert.NoError(conn.Close()) }()
	sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, client.deviceSize))
	ranges, fds, _ := readUffdRangeResponse(t, conn)
	defer closeRawFds(fds)

	if !assert.NotEmpty(ranges) || !assert.Len(fds, len(ranges)) {
		return
	}
	last := ranges[len(ranges)-1]
	assert.True(util.IsCharDevice(t, fds[len(fds)-1]),
		"fixture must expose a /dev/zero tail hole for the zero-page case")
	assert.Equal(client.deviceSize, last.deviceOffset+last.length, "tail hole must reach the device end")

	tailOffset := client.deviceSize - uint64(client.blockSize)
	assert.GreaterOrEqual(tailOffset, last.deviceOffset, "tail block must be inside the zero hole")

	// Fault the tail block in and check the whole block reads as zero.
	tailBlock := waitUffdTouch(t, client.touchAsync(tailOffset, uint64(client.blockSize)), uffdFaultDeadline, "zero-page fault at device tail")
	assert.Equal(make([]byte, client.blockSize), tailBlock, "the whole tail block must be zero after the fault")
}

// TestUffdRealFaultZerocopy verifies zerocopy fault completion: the fault
// produces RANGE_RESPONSE frames
// with backing FDs, the client installs fixed mappings and wakes the fault
// with UFFDIO_WAKE, and the resumed read observes the right bytes.
func TestUffdRealFaultZerocopy(t *testing.T) {
	requireUffdRunner(t)
	assert := assert.New(t)
	fixture := newUffdFixture(t, uffdFixtureOptions{})

	// A handshake without the copy flag selects zerocopy.
	faultSize := uint64(64 * 1024)
	client := newUffdFaultClient(t, fixture, 0, faultSize, 0)
	client.assertHandshakeAccepted(t)

	expected := fetchUffdDeviceBytes(t, fixture.socketPath, 0, client.deviceSize)

	// Fault 1: non-zero data at device offset 0 (EROFS metadata).
	ch := client.touchAsync(0, 1)
	ranges, _ := client.serveOneZerocopyFault(t)
	assert.NotEmpty(ranges)
	b := waitUffdTouch(t, ch, uffdFaultDeadline, "zerocopy fault at device offset 0")
	assert.Equal(expected[0], b[0])
	window := waitUffdTouch(t, client.touchAsync(0, faultSize), uffdFaultDeadline, "read of zerocopy-mapped fault window")
	util.CheckBytesEqual(t, expected[:faultSize], window, "zerocopy-mapped fault window")

	// Fault 2: the device tail hole must map as zero pages.
	tailOffset := client.deviceSize - faultSize
	ch = client.touchAsync(tailOffset, 1)
	_, _ = client.serveOneZerocopyFault(t)
	b = waitUffdTouch(t, ch, uffdFaultDeadline, "zerocopy fault at device tail")
	assert.Zero(b[0])
	tail := waitUffdTouch(t, client.touchAsync(tailOffset, faultSize), uffdFaultDeadline, "read of zerocopy-mapped tail window")
	util.CheckBytesEqual(t, expected[tailOffset:], tail, "zerocopy-mapped tail window")

	// Warm: the fixed mappings stay installed, so repeated reads are stable
	// and need no further service round trip.
	warm := waitUffdTouch(t, client.touchAsync(0, faultSize), uffdFaultDeadline, "warm re-read of zerocopy fault window")
	util.CheckBytesEqual(t, expected[:faultSize], warm, "warm re-read of zerocopy fault window")
}

// TestUffdPrefaultAndBatching verifies the HANDSHAKE prefault path and the
// multi-batch RANGE_RESPONSE contract: a merged multi-blob image warms
// the cache, the prefault response spans more than one batch, and mapping
// every returned range yields a byte-exact device view without any further
// faults.
func TestUffdPrefaultAndBatching(t *testing.T) {
	requireUffdRunner(t)
	assert := assert.New(t)
	fixture := newUffdFixture(t, uffdFixtureOptions{blobCount: 20})

	// Warm the whole cache so the prefault probe resolves every blob range,
	// and keep the assembled bytes as the reference.
	probe := dialUffdSocket(t, fixture.socketPath)
	deviceSize, _ := statUffdDevice(t, probe)
	assert.NoError(probe.Close())
	expected := fetchUffdDeviceBytes(t, fixture.socketPath, 0, deviceSize)

	// The prefault response must span more than one batch.
	client := newUffdFaultClient(t, fixture, uffdHandshakeFlagPrefault, 2*1024*1024, 0)
	ranges, fds, batches := client.readRangeBatches(t, uffdCaseDeadline)
	defer closeRawFds(fds)
	assert.Greater(len(ranges), uffdMaxRangesPerMsg,
		"multi-blob fixture must force more ranges than one RANGE_RESPONSE batch carries")
	assert.GreaterOrEqual(batches, 2, "prefault must span at least two RANGE_RESPONSE batches")

	client.mapRanges(t, ranges, fds, false)
	client.assertHandshakeAccepted(t)

	// The warm prefault covered the whole device, so a full read needs no
	// fault service at all; the deadline catches any uncovered page.
	snapshot := waitUffdTouch(t, client.touchAsync(0, client.deviceSize), uffdCaseDeadline, "full read of prefault-mapped device")
	util.CheckBytesEqual(t, expected, snapshot, "prefault-mapped memory vs device reference")
}

// TestUffdNegativeProtocol drives the malformed/unsupported input corpus:
// every invalid frame must fail closed, that is the
// connection terminates without a success-shaped response and without
// hanging, while the service stays alive for new sessions. Unknown message
// types and unknown header flag bits must be tolerated per the v1 rules.
func TestUffdNegativeProtocol(t *testing.T) {
	fixture := newUffdFixture(t, uffdFixtureOptions{})

	probe := dialUffdSocket(t, fixture.socketPath)
	deviceSize, blockSize := statUffdDevice(t, probe)
	assert.NoError(t, probe.Close())

	// A /dev/null descriptor stands in for a userfaultfd where a case attaches
	// FDs the message must reject.
	devNull, err := os.Open("/dev/null")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { assert.NoError(t, devNull.Close()) }()
	devNullFd := int(devNull.Fd())

	handshakePayload := func(version uint16, regionCount byte, regions int) []byte {
		payload := make([]byte, 4+regions*uffdRegionSize)
		binary.LittleEndian.PutUint16(payload[0:2], version)
		payload[3] = regionCount
		return payload
	}

	tests := []struct {
		name string
		send func(t *testing.T, conn *net.UnixConn)
	}{
		{
			name: "bad magic",
			send: func(t *testing.T, conn *net.UnixConn) {
				writeRawUffdFrame(t, conn, 0xdeadbeef, 0, uffdMsgStatRequest, 0, nil, nil)
			},
		},
		{
			name: "oversized payload length",
			send: func(t *testing.T, conn *net.UnixConn) {
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgFetchRequest, 1<<20, nil, nil)
			},
		},
		{
			name: "truncated payload",
			send: func(t *testing.T, conn *net.UnixConn) {
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgFetchRequest, uffdFetchRequestSize, make([]byte, 8), nil)
				assert.NoError(t, conn.CloseWrite())
			},
		},
		{
			name: "handshake unsupported version",
			send: func(t *testing.T, conn *net.UnixConn) {
				payload := handshakePayload(uffdProtocolVersion+1, 0, 0)
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, []int{devNullFd})
			},
		},
		{
			name: "handshake missing fd",
			send: func(t *testing.T, conn *net.UnixConn) {
				payload := handshakePayload(uffdProtocolVersion, 0, 0)
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, nil)
			},
		},
		{
			name: "handshake extra fds",
			send: func(t *testing.T, conn *net.UnixConn) {
				payload := handshakePayload(uffdProtocolVersion, 0, 0)
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, []int{devNullFd, devNullFd})
			},
		},
		{
			name: "handshake malformed regions",
			send: func(t *testing.T, conn *net.UnixConn) {
				// The region count says one region but no region bytes follow.
				payload := handshakePayload(uffdProtocolVersion, 1, 0)
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, []int{devNullFd})
			},
		},
		{
			name: "stat with payload",
			send: func(t *testing.T, conn *net.UnixConn) {
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgStatRequest, 4, make([]byte, 4), nil)
			},
		},
		{
			name: "stat with unexpected fd",
			send: func(t *testing.T, conn *net.UnixConn) {
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgStatRequest, 0, nil, []int{devNullFd})
			},
		},
		{
			name: "fetch with unexpected fd",
			send: func(t *testing.T, conn *net.UnixConn) {
				payload := encodeUffdDeviceRange(0, uint64(blockSize))
				writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgFetchRequest, uint32(len(payload)), payload, []int{devNullFd})
			},
		},
		{
			name: "fetch zero length",
			send: func(t *testing.T, conn *net.UnixConn) {
				sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, 0))
			},
		},
		{
			name: "fetch unaligned",
			send: func(t *testing.T, conn *net.UnixConn) {
				sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(123, uint64(blockSize)))
			},
		},
		{
			name: "fetch out of bounds",
			send: func(t *testing.T, conn *net.UnixConn) {
				sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(deviceSize, uint64(blockSize)))
			},
		},
		{
			name: "fetch offset overflow",
			send: func(t *testing.T, conn *net.UnixConn) {
				overflow := ^uint64(0) - uint64(blockSize) + 1
				sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(overflow, 2*uint64(blockSize)))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialUffdSocket(t, fixture.socketPath)
			defer func() { _ = conn.Close() }()
			tc.send(t, conn)
			assertUffdConnFailsClosed(t, conn)
			assertUffdServiceAlive(t, fixture.socketPath, deviceSize)
		})
	}

	t.Run("unknown message type ignored", func(t *testing.T) {
		assert := assert.New(t)

		// v1 forward compatibility: unknown message types are logged and
		// ignored; the connection keeps working.
		conn := dialUffdSocket(t, fixture.socketPath)
		defer func() { assert.NoError(conn.Close()) }()
		writeRawUffdFrame(t, conn, uffdMagic, 0, 0x55, 0, nil, nil)
		size, _ := statUffdDevice(t, conn)
		assert.Equal(deviceSize, size)
	})

	t.Run("unknown header flags ignored", func(t *testing.T) {
		assert := assert.New(t)

		// v1 forward compatibility: unknown header flag bits are ignored.
		conn := dialUffdSocket(t, fixture.socketPath)
		defer func() { assert.NoError(conn.Close()) }()
		writeRawUffdFrame(t, conn, uffdMagic, 0x8000, uffdMsgStatRequest, 0, nil, nil)
		header, payload, fds := readUffdFrame(t, conn)
		assert.Equal(uint16(uffdMsgStatResponse), header.msgType)
		assert.Empty(fds)
		assert.Len(payload, uffdStatResponseSize)
	})
}

// writeRawUffdFrame writes an arbitrary (possibly malformed) protocol frame:
// the declared payload length may disagree with the bytes actually sent, and
// FDs may be attached to any message type.
func writeRawUffdFrame(t *testing.T, conn *net.UnixConn, magic uint32, flags, msgType uint16, declaredLen uint32, payload []byte, fds []int) {
	t.Helper()
	frame := make([]byte, uffdHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(frame[0:4], magic)
	binary.LittleEndian.PutUint16(frame[4:6], flags)
	binary.LittleEndian.PutUint16(frame[6:8], msgType)
	binary.LittleEndian.PutUint32(frame[16:20], declaredLen)
	copy(frame[uffdHeaderSize:], payload)

	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}
	n, oobn, err := conn.WriteMsgUnix(frame, rights, nil)
	assert.NoError(t, err)
	assert.Equal(t, len(frame), n)
	assert.Equal(t, len(rights), oobn)
}

// assertUffdConnFailsClosed asserts the fail-closed contract: within the
// deadline the service must terminate the connection without sending any
// success-shaped response and without hanging.
func assertUffdConnFailsClosed(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	assert.NoError(t, conn.SetReadDeadline(time.Now().Add(uffdFaultDeadline)))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	assert.Error(t, err, "expected the connection to fail closed, got %d response byte(s)", n)
	assert.False(t, os.IsTimeout(err),
		"service neither responded nor closed the connection within the deadline (hang)")
}

// assertUffdServiceAlive asserts the service survived a poisoned connection
// and still answers a fresh session.
func assertUffdServiceAlive(t *testing.T, socketPath string, wantDeviceSize uint64) {
	t.Helper()
	conn := dialUffdSocket(t, socketPath)
	defer func() { assert.NoError(t, conn.Close()) }()
	size, _ := statUffdDevice(t, conn)
	assert.Equal(t, wantDeviceSize, size)
}

// TestUffdBackendFailure verifies bounded fail-closed behaviour when the
// local backend is corrupted: the request
// terminates within its deadline, zero wrong bytes are returned, and the
// service keeps serving new sessions.
func TestUffdBackendFailure(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, fixture *uffdFixture)
	}{
		{
			name: "backend truncated",
			corrupt: func(t *testing.T, fixture *uffdFixture) {
				for _, blob := range fixture.fullBlobs {
					assert.NoError(t, os.Truncate(blob, 1024))
				}
			},
		},
		{
			name: "backend removed",
			corrupt: func(t *testing.T, fixture *uffdFixture) {
				for _, blob := range fixture.fullBlobs {
					assert.NoError(t, os.Remove(blob))
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newUffdFixture(t, uffdFixtureOptions{beforeStart: tc.corrupt})
			probe := dialUffdSocket(t, fixture.socketPath)
			deviceSize, _ := statUffdDevice(t, probe)
			assert.NoError(t, probe.Close())

			// A cold FETCH over the whole device must hit the corrupted
			// backend and fail closed: no RANGE_RESPONSE (zero wrong bytes),
			// the connection terminates within the deadline.
			conn := dialUffdSocket(t, fixture.socketPath)
			defer func() { _ = conn.Close() }()
			sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, deviceSize))
			assertUffdConnFailsClosed(t, conn)

			// The unverified ranges must not have been marked ready: a
			// second cold FETCH fails closed the same way.
			second := dialUffdSocket(t, fixture.socketPath)
			defer func() { _ = second.Close() }()
			sendUffdRequest(t, second, uffdMsgFetchRequest, encodeUffdDeviceRange(0, deviceSize))
			assertUffdConnFailsClosed(t, second)
			assertUffdServiceAlive(t, fixture.socketPath, deviceSize)
		})
	}
}

// uffdChildLog writes one protocol line to stdout with a raw write syscall:
// after the deliberately-unresolvable fault is issued the child's Go runtime
// timers are starved, so nothing on this path may depend on them.
func uffdChildLog(format string, args ...any) {
	_, _ = unix.Write(1, []byte(fmt.Sprintf(format+"\n", args...)))
}

// uffdChildFail writes an error line to stderr and returns the child's
// failure exit code.
func uffdChildFail(format string, args ...any) int {
	_, _ = unix.Write(2, []byte(fmt.Sprintf("ERROR: "+format+"\n", args...)))
	return 1
}

// uffdChildEnvUint parses the unsigned integer in the environment variable
// name.
func uffdChildEnvUint(name string) (uint64, error) {
	value := os.Getenv(name)
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", name, value, err)
	}

	return n, nil
}

// runUffdOutstandingFaultChild is the re-exec target for
// TestUffdLifecycle/disconnect_with_outstanding_fault. It opens a session whose
// HANDSHAKE declares only a prefix of the device, issues a read outside that
// declared region (which therefore stays outstanding), and on any stdin input
// tears the session down, socket first, then its userfaultfd copy, so the
// blocked read must resolve as an anonymous zero page.
//
// Protocol on stdout: READY (session live), TOUCHING (immediately before the
// outstanding read), RESOLVED <byte> (read completed after teardown), DONE.
func runUffdOutstandingFaultChild() int {
	socketPath := os.Getenv(uffdChildSocketEnv)
	if socketPath == "" {
		return uffdChildFail("%s not set", uffdChildSocketEnv)
	}
	deviceSize, err := uffdChildEnvUint(uffdChildDeviceSizeEnv)
	if err != nil {
		return uffdChildFail("%v", err)
	}
	blockSize, err := uffdChildEnvUint(uffdChildBlockSizeEnv)
	if err != nil {
		return uffdChildFail("%v", err)
	}
	regionSize, err := uffdChildEnvUint(uffdChildRegionSizeEnv)
	if err != nil {
		return uffdChildFail("%v", err)
	}
	if regionSize == 0 || regionSize >= deviceSize || deviceSize < blockSize {
		return uffdChildFail("invalid geometry: device=%d region=%d block=%d", deviceSize, regionSize, blockSize)
	}

	// Register the whole device with a fresh userfaultfd.
	vma, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return uffdChildFail("anonymous VMA mmap: %v", err)
	}

	rawFd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
	if errno != 0 {
		return uffdChildFail("userfaultfd syscall: %v", errno)
	}
	uffd := int(rawFd)
	api := uffdioAPIArg{api: uffdAPIVersion}
	if err := uffdIoctl(uffd, uffdioAPIIoctl, unsafe.Pointer(&api)); err != nil {
		return uffdChildFail("UFFDIO_API: %v", err)
	}
	base := uint64(uintptr(unsafe.Pointer(&vma[0])))
	register := uffdioRegisterArg{
		rangeArg: uffdioRangeArg{start: base, len: deviceSize},
		mode:     uffdRegisterMissing,
	}
	if err := uffdIoctl(uffd, uffdioRegisterIoctl, unsafe.Pointer(&register)); err != nil {
		return uffdChildFail("UFFDIO_REGISTER: %v", err)
	}

	// Declare only the region prefix in the HANDSHAKE.
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return uffdChildFail("dial %s: %v", socketPath, err)
	}
	if err := conn.SetDeadline(time.Now().Add(uffdFaultDeadline)); err != nil {
		return uffdChildFail("set deadline: %v", err)
	}
	region := uffdVmaRegion{
		virtAddr:  base,
		size:      regionSize,
		offset:    0,
		faultSize: blockSize,
		prot:      int32(unix.PROT_READ | unix.PROT_WRITE),
		flags:     int32(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
	}
	frame := encodeUffdHandshakeFrame(uffdProtocolVersion, uffdHandshakeFlagCopy, []uffdVmaRegion{region})
	if _, _, err := conn.WriteMsgUnix(frame, unix.UnixRights(uffd), nil); err != nil {
		return uffdChildFail("HANDSHAKE send: %v", err)
	}

	// A STAT round trip proves the handshake was accepted: a rejected
	// handshake terminates the connection. Timers still work here since the
	// outstanding fault has not been issued yet.
	size, _, err := tryStatUffdDevice(conn)
	if err != nil {
		return uffdChildFail("post-handshake STAT: %v", err)
	}
	if size != deviceSize {
		return uffdChildFail("post-handshake STAT: device size %d, want %d", size, deviceSize)
	}
	uffdChildLog("READY")

	// Issue the deliberately-unresolvable read on its own goroutine. From
	// TOUCHING onward the runtime's timers may be starved, so the rest of
	// this process uses only raw syscalls and channel operations.
	resolved := make(chan byte, 1)
	go func() {
		uffdChildLog("TOUCHING")
		resolved <- vma[deviceSize-blockSize]
	}()

	// Block on stdin with a raw read: any input (or EOF if the parent dies)
	// triggers the teardown.
	buf := make([]byte, 1)
	_, _ = unix.Read(0, buf)

	// Drop the socket so the service releases its userfaultfd copy, then
	// drop our copy: with no userfaultfd left the kernel resolves the
	// blocked read as a plain anonymous fault (zero page).
	_ = conn.Close()
	_ = unix.Close(uffd)

	b := <-resolved
	uffdChildLog("RESOLVED %d", b)
	if b != 0 {
		return uffdChildFail("outstanding fault resolved with wrong byte %#02x, want zero page", b)
	}

	uffdChildLog("DONE")

	return 0
}

// TestUffdLifecycle verifies connection and service lifecycle behaviour:
// client disconnect with and without an
// outstanding fault, graceful service stop with an active session, socket
// cleanup, stale-socket takeover and a fresh session after restart.
func TestUffdLifecycle(t *testing.T) {
	requireUffdRunner(t)
	fixture := newUffdFixture(t, uffdFixtureOptions{})

	probe := dialUffdSocket(t, fixture.socketPath)
	deviceSize, _ := statUffdDevice(t, probe)
	assert.NoError(t, probe.Close())

	t.Run("client disconnect", func(t *testing.T) {
		client := newUffdFaultClient(t, fixture, uffdHandshakeFlagCopy, uint64(uffdChunkSize), 0)
		client.assertHandshakeAccepted(t)
		client.close(t)
		assertUffdServiceAlive(t, fixture.socketPath, deviceSize)
	})

	t.Run("disconnect with outstanding fault", func(t *testing.T) {
		assert := assert.New(t)

		// The child (re-exec of this binary, see TestMain) declares only the
		// first half of the device in its HANDSHAKE and reads a page in the
		// second half, so that fault stays deliberately outstanding. It runs
		// out of process because an unresolved userfaultfd fault starves the
		// Go runtime timers of the faulting process.
		regionSize := util.AlignDown(deviceSize/2, uint64(uffdChunkSize))
		assert.Greater(regionSize, uint64(0), "device too small to split")

		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			uffdChildModeEnv+"="+uffdChildModeOutstandingFault,
			uffdChildSocketEnv+"="+fixture.socketPath,
			fmt.Sprintf("%s=%d", uffdChildDeviceSizeEnv, deviceSize),
			fmt.Sprintf("%s=%d", uffdChildBlockSizeEnv, uffdChunkSize),
			fmt.Sprintf("%s=%d", uffdChildRegionSizeEnv, regionSize),
		)
		stdin, err := cmd.StdinPipe()
		assert.NoError(err)
		stdout, err := cmd.StdoutPipe()
		assert.NoError(err)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if !assert.NoError(cmd.Start()) {
			return
		}
		defer func() {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

		// Follow the child's protocol lines under the case deadline.
		lines := make(chan string, 16)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				lines <- scanner.Text()
			}
			close(lines)
		}()

		nextLine := func(desc string) string {
			select {
			case line, ok := <-lines:
				if !assert.True(ok, "child exited before printing %s:\n%s", desc, stderr.String()) {
					t.FailNow()
				}
				return line
			case <-time.After(uffdCaseDeadline):
				t.Fatalf("timed out waiting for child %s:\n%s", desc, stderr.String())
				return ""
			}
		}

		assert.Equal("READY", nextLine("READY"))
		assert.Equal("TOUCHING", nextLine("TOUCHING"))

		// The fault targets a page outside the declared region, so it must
		// stay outstanding: no RESOLVED line within the grace window.
		select {
		case line := <-lines:
			t.Fatalf("fault outside the declared region must stay outstanding, child printed %q", line)
		case <-time.After(time.Second):
		}

		// Tear the session down while the fault is outstanding. Once both
		// userfaultfd copies (service side via disconnect, child side via
		// close) are gone, the blocked read resolves as an anonymous zero
		// page, never as wrong data, within the case deadline.
		_, err = io.WriteString(stdin, "close\n")
		assert.NoError(err)
		assert.Equal("RESOLVED 0", nextLine("RESOLVED"))
		assert.Equal("DONE", nextLine("DONE"))

		// The child must exit cleanly and the service must survive it.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			assert.NoError(err, "child must exit cleanly:\n%s", stderr.String())
		case <-time.After(uffdCaseDeadline):
			_ = cmd.Process.Kill()
			t.Fatalf("child did not exit within %v of teardown:\n%s", uffdCaseDeadline, stderr.String())
		}
		assertUffdServiceAlive(t, fixture.socketPath, deviceSize)
	})

	t.Run("service stop with active session", func(t *testing.T) {
		assert := assert.New(t)
		client := newUffdFaultClient(t, fixture, uffdHandshakeFlagCopy, uint64(uffdChunkSize), 0)
		client.assertHandshakeAccepted(t)

		// Stop the service under SIGTERM while the session is live; a clean
		// stop logs that it stopped.
		service := fixture.service
		assert.True(service.Stop(), "service must exit on SIGTERM:\n%s", service.Logs())
		assert.Positive(service.CountLogs("nydus uffd service stopped"), "service must stop cleanly:\n%s", service.Logs())

		// Graceful stop removes the Unix socket; the client observes EOF.
		_, err := os.Stat(fixture.socketPath)
		assert.True(os.IsNotExist(err), "service must remove its socket on shutdown")
		assertUffdConnFailsClosed(t, client.conn)
		client.close(t)
	})

	t.Run("restart with stale socket", func(t *testing.T) {
		assert := assert.New(t)

		// A leftover socket path must not block a restart, and a fresh
		// session against the restarted service must work (v1 promises new
		// sessions after restart, not transparent reconnect/resume).
		fixture.service.Stop()
		assert.NoError(os.WriteFile(fixture.socketPath, nil, 0o644))
		fixture.start(t)

		client := newUffdFaultClient(t, fixture, uffdHandshakeFlagCopy, uint64(uffdChunkSize), 0)
		client.assertHandshakeAccepted(t)
		b := waitUffdTouch(t, client.touchAsync(0, 1), uffdFaultDeadline, "cold fault after service restart")
		expected := fetchUffdDeviceBytes(t, fixture.socketPath, 0, uint64(uffdChunkSize))
		assert.Equal(expected[0], b[0], "restarted service must resolve faults for new sessions")
	})
}
