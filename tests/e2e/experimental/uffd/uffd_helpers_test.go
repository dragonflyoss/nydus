package uffd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Wire protocol v1, matching nydus/src/uffd.
const (
	magic = 0x5546_4644

	msgHandshake     = 0x01
	msgStat          = 0x02
	msgFetch         = 0x03
	msgProbe         = 0x04
	msgRangeResponse = 0x81
	msgStatResponse  = 0x82

	flagNext = 1 << 0

	headerSize       = 20
	rangeSize        = 24
	statResponseSize = 16
	rangeCountSize   = 4
	fetchRequestSize = 16
	regionSize       = 40
	maxRangesPerMsg  = 16

	protocolVersion   = 1
	handshakeCopy     = 0x01
	handshakePrefault = 0x02
)

const (
	// blockSize is the device block size the service reports, and the
	// chunk size of the images.
	blockSize = 4096

	// A single fault must complete within faultDeadline, and nothing a
	// case waits for may take longer than caseDeadline.
	faultDeadline = 10 * time.Second
	caseDeadline  = 30 * time.Second

	erofsSuperOffset = 1024
	erofsSuperMagic  = 0xE0F5E1E2
)

// Linux userfaultfd ABI, matching nydus/src/uffd/core.rs.
const (
	uffdioAPIIoctl      = 0xc018aa3f // UFFDIO_API
	uffdioRegisterIoctl = 0xc020aa00 // UFFDIO_REGISTER
	uffdioWakeIoctl     = 0x8010aa02 // UFFDIO_WAKE
	uffdAPIVersion      = 0xAA
	uffdRegisterMissing = 0x1 // UFFDIO_REGISTER_MODE_MISSING

	// _UFFDIO_* bits reported in uffdio_register.ioctls.
	uffdioBitWake     = 1 << 0x02
	uffdioBitCopy     = 1 << 0x03
	uffdioBitZeropage = 1 << 0x04
	uffdioRequired    = uffdioBitWake | uffdioBitCopy | uffdioBitZeropage
)

// The outstanding-fault child of TestLifecycle is this test binary run
// again with these variables set; see TestMain.
const (
	childModeEnv              = "NYDUS_E2E_UFFD_CHILD_MODE"
	childModeOutstandingFault = "outstanding-fault"
	childSocketEnv            = "NYDUS_E2E_UFFD_CHILD_SOCKET"
	childDeviceSizeEnv        = "NYDUS_E2E_UFFD_CHILD_DEVICE_SIZE"
	childRegionSizeEnv        = "NYDUS_E2E_UFFD_CHILD_REGION_SIZE"
)

type uffdioAPIArg struct {
	api      uint64
	features uint64
	ioctls   uint64
}

type uffdioRangeArg struct {
	start uint64
	len   uint64
}

type uffdioRegisterArg struct {
	rng    uffdioRangeArg
	mode   uint64
	ioctls uint64
}

func uffdIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// newUserfaultfd opens a userfaultfd and completes the UFFDIO_API handshake.
func newUserfaultfd() (int, error) {
	rawFd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
	if errno != 0 {
		return -1, fmt.Errorf("userfaultfd syscall unavailable: %v (check vm.unprivileged_userfaultfd or run as root)", errno)
	}
	fd := int(rawFd)
	api := uffdioAPIArg{api: uffdAPIVersion}
	if err := uffdIoctl(fd, uffdioAPIIoctl, unsafe.Pointer(&api)); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("UFFDIO_API handshake failed: %v", err)
	}
	return fd, nil
}

// registerMissing registers [base, base+size) in MISSING mode and checks
// the kernel offers every ioctl the service relies on.
func registerMissing(fd int, base, size uint64) error {
	reg := uffdioRegisterArg{rng: uffdioRangeArg{start: base, len: size}, mode: uffdRegisterMissing}
	if err := uffdIoctl(fd, uffdioRegisterIoctl, unsafe.Pointer(&reg)); err != nil {
		return fmt.Errorf("UFFDIO_REGISTER (MISSING mode) failed: %v", err)
	}
	if reg.ioctls&uffdioRequired != uffdioRequired {
		return fmt.Errorf("required UFFD ioctls missing: have %#x, need WAKE|COPY|ZEROPAGE (%#x)", reg.ioctls, uint64(uffdioRequired))
	}
	return nil
}

// probeCapability checks every userfaultfd capability the suite depends on:
// the syscall, the UFFDIO_API handshake, MISSING-mode registration and the
// UFFDIO_COPY/ZEROPAGE/WAKE ioctls.
func probeCapability() error {
	fd, err := newUserfaultfd()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	pageSize := unix.Getpagesize()
	mem, err := unix.Mmap(-1, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("anonymous mmap failed: %v", err)
	}
	defer func() { _ = unix.Munmap(mem) }()
	return registerMissing(fd, uint64(uintptr(unsafe.Pointer(&mem[0]))), uint64(pageSize))
}

// requireUserfaultfd requires the runner to support real userfaultfd faults.
func requireUserfaultfd(t *testing.T) {
	t.Helper()
	err := probeCapability()
	env.Require(t, err == nil, "runner lacks userfaultfd: %v", err)
}

var subcommands sync.Map

// requireSubcommand requires a nydus binary built with the feature that
// provides the subcommand.
func requireSubcommand(t env.TB, name string) {
	t.Helper()
	nydus := env.Nydus(t)
	ok, cached := subcommands.Load(name)
	if !cached {
		ok = exec.Command(nydus, name, "--help").Run() == nil
		subcommands.Store(name, ok)
	}
	env.Require(t, ok.(bool), "%s lacks the %s subcommand (build with FEATURES=...,%s)", nydus, name, name)
}

// standardImage is the Standard corpus with 4K chunks, which leaves a
// /dev/zero hole at the device tail.
func standardImage(t *testing.T) fixture.Image {
	t.Helper()
	layout, err := fixture.LayoutByName("zstd-4k")
	require.NoError(t, err)
	return fixture.Build(t, fixture.Standard, layout)
}

// layeredImage merges n one-file layers, one blob each, so FETCH, PROBE and
// prefault return more ranges than one RANGE_RESPONSE frame carries.
func layeredImage(t *testing.T, n int) fixture.Image {
	t.Helper()
	layout, err := fixture.LayoutByName("zstd-4k")
	require.NoError(t, err)
	dir := env.WorkDir(t)
	blobDir := filepath.Join(dir, "blobs")
	var blobs []string
	for i := range n {
		name := fmt.Sprintf("layer-%02d", i)
		src := filepath.Join(dir, name)
		corpus.NewCorpus(t, src).CreateFile(t, name+".bin", bytes.Repeat([]byte{byte(i + 1)}, 8192+i*512))
		blob, _ := fixture.BuildInto(t, blobDir, filepath.Join(dir, name+".bootstrap"), src, layout)
		blobs = append(blobs, blob)
	}
	// `nydus merge` names each layer's blob after its file, so it merges
	// the blobs, which embed their bootstraps.
	bootstrap := filepath.Join(dir, "merged.bootstrap")
	fixture.Run(t, env.Nydus(t), append([]string{"merge", "--bootstrap", bootstrap}, blobs...)...)
	return fixture.Image{
		Name:      fmt.Sprintf("layers-%d", n),
		Layout:    layout,
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     blobs,
		Merged:    true,
	}
}

const daemonName = "nydus-uffd"

// service is a `nydus uffd` daemon serving one image on a Unix socket.
type service struct {
	img    fixture.Image
	dir    string
	config string
	socket string
	daemon *mount.Daemon
}

// startService serves img with a fresh cache.
func startService(t *testing.T, img fixture.Image) *service {
	t.Helper()
	requireSubcommand(t, "uffd")
	dir := env.WorkDir(t)
	cache := filepath.Join(dir, "cache")
	require.NoError(t, os.MkdirAll(cache, 0o755))
	s := &service{
		img:    img,
		dir:    dir,
		config: mount.LocalConfig(img.BlobDir, cache).Write(t, dir, "config.json"),
		socket: mount.SocketPath(t),
	}
	s.start(t)
	return s
}

// start (re)starts the daemon and waits until its socket accepts.
func (s *service) start(t *testing.T) {
	t.Helper()
	s.daemon = mount.StartDaemon(t, s.dir, daemonName, env.Nydus(t), "uffd",
		"--bootstrap", s.img.Bootstrap,
		"--config", s.config,
		"--socket", s.socket,
		"--threads", "1",
		"--log-level", "info",
		"--log-dir", mount.LogDir(s.dir, daemonName),
	)
	s.daemon.WaitFor(t, caseDeadline, "socket "+s.socket, func() bool {
		conn, err := net.DialTimeout("unix", s.socket, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

// deviceSize returns the device size over a throwaway session.
func (s *service) deviceSize(t *testing.T) uint64 {
	t.Helper()
	conn := dial(t, s.socket)
	defer func() { _ = conn.Close() }()
	size, _ := stat(t, conn)
	return size
}

type header struct {
	flags   uint16
	msgType uint16
	length  uint32
}

// deviceRange maps [deviceOffset, +length) of the device onto fileOffset of
// the backing fd sent with it.
type deviceRange struct {
	deviceOffset uint64
	fileOffset   uint64
	length       uint64
}

type vmaRegion struct {
	virtAddr  uint64
	size      uint64
	offset    uint64
	faultSize uint64
	prot      int32
	flags     int32
}

func dial(t *testing.T, socket string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	require.NoError(t, err)
	return conn
}

func encodeHeader(magic uint32, flags, msgType uint16, length uint32) []byte {
	h := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(h[0:4], magic)
	binary.LittleEndian.PutUint16(h[4:6], flags)
	binary.LittleEndian.PutUint16(h[6:8], msgType)
	binary.LittleEndian.PutUint32(h[16:20], length)
	return h
}

func send(t *testing.T, conn *net.UnixConn, msgType uint16, payload []byte) {
	t.Helper()
	_, err := conn.Write(append(encodeHeader(magic, 0, msgType, uint32(len(payload))), payload...))
	require.NoError(t, err)
}

// writeRawFrame writes an arbitrary, possibly malformed frame: the declared
// payload length may disagree with the bytes sent, and fds may ride on any
// message type.
func writeRawFrame(t *testing.T, conn *net.UnixConn, magic uint32, flags, msgType uint16, declaredLen uint32, payload []byte, fds []int) {
	t.Helper()
	frame := append(encodeHeader(magic, flags, msgType, declaredLen), payload...)
	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}
	n, oobn, err := conn.WriteMsgUnix(frame, rights, nil)
	require.NoError(t, err)
	require.Equal(t, len(frame), n)
	require.Equal(t, len(rights), oobn)
}

func encodeRange(offset, length uint64) []byte {
	payload := make([]byte, fetchRequestSize)
	binary.LittleEndian.PutUint64(payload[0:8], offset)
	binary.LittleEndian.PutUint64(payload[8:16], length)
	return payload
}

func encodeHandshake(version uint16, flags byte, regions []vmaRegion) []byte {
	payloadLen := 4 + len(regions)*regionSize
	frame := make([]byte, headerSize+payloadLen)
	copy(frame, encodeHeader(magic, 0, msgHandshake, uint32(payloadLen)))
	binary.LittleEndian.PutUint16(frame[20:22], version)
	frame[22] = flags
	frame[23] = byte(len(regions))
	off := 24
	for _, r := range regions {
		binary.LittleEndian.PutUint64(frame[off:off+8], r.virtAddr)
		binary.LittleEndian.PutUint64(frame[off+8:off+16], r.size)
		binary.LittleEndian.PutUint64(frame[off+16:off+24], r.offset)
		binary.LittleEndian.PutUint64(frame[off+24:off+32], r.faultSize)
		binary.LittleEndian.PutUint32(frame[off+32:off+36], uint32(r.prot))
		binary.LittleEndian.PutUint32(frame[off+36:off+40], uint32(r.flags))
		off += regionSize
	}
	return frame
}

// readFrame reads one frame with the fds sent along with it.
func readFrame(t *testing.T, conn *net.UnixConn) (header, []byte, []int) {
	t.Helper()
	buf := make([]byte, 64*1024)
	oob := make([]byte, 4096)
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, headerSize)
	require.Equal(t, uint32(magic), binary.LittleEndian.Uint32(buf[0:4]), "response magic")
	h := header{
		flags:   binary.LittleEndian.Uint16(buf[4:6]),
		msgType: binary.LittleEndian.Uint16(buf[6:8]),
		length:  binary.LittleEndian.Uint32(buf[16:20]),
	}
	end := min(n, headerSize+int(h.length))
	payload := append([]byte(nil), buf[headerSize:end]...)
	if rest := int(h.length) - len(payload); rest > 0 {
		extra := make([]byte, rest)
		_, err := io.ReadFull(conn, extra)
		require.NoError(t, err)
		payload = append(payload, extra...)
	}
	return h, payload, parseUnixRights(t, oob[:oobn])
}

func parseUnixRights(t *testing.T, oob []byte) []int {
	t.Helper()
	if len(oob) == 0 {
		return nil
	}
	messages, err := syscall.ParseSocketControlMessage(oob)
	require.NoError(t, err)
	var fds []int
	for _, message := range messages {
		rights, err := syscall.ParseUnixRights(&message)
		require.NoError(t, err)
		fds = append(fds, rights...)
	}
	return fds
}

func decodeRanges(t *testing.T, payload []byte) []deviceRange {
	t.Helper()
	require.GreaterOrEqual(t, len(payload), rangeCountSize)
	count := int(binary.LittleEndian.Uint32(payload[0:4]))
	require.Len(t, payload, rangeCountSize+count*rangeSize)
	ranges := make([]deviceRange, 0, count)
	for off := rangeCountSize; off < len(payload); off += rangeSize {
		ranges = append(ranges, deviceRange{
			deviceOffset: binary.LittleEndian.Uint64(payload[off : off+8]),
			fileOffset:   binary.LittleEndian.Uint64(payload[off+8 : off+16]),
			length:       binary.LittleEndian.Uint64(payload[off+16 : off+24]),
		})
	}
	return ranges
}

// readRangeResponse collects one logical RANGE_RESPONSE, possibly split
// over NEXT-linked frames, and returns its ranges, their fds and the
// number of frames.
func readRangeResponse(t *testing.T, conn *net.UnixConn) ([]deviceRange, []int, int) {
	t.Helper()
	var ranges []deviceRange
	var fds []int
	for frames := 1; ; frames++ {
		h, payload, frameFds := readFrame(t, conn)
		require.Equal(t, uint16(msgRangeResponse), h.msgType)
		frameRanges := decodeRanges(t, payload)
		require.Len(t, frameFds, len(frameRanges), "one fd per range")
		ranges = append(ranges, frameRanges...)
		fds = append(fds, frameFds...)
		if h.flags&flagNext == 0 {
			return ranges, fds, frames
		}
	}
}

func closeFds(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func withReadDeadline(t *testing.T, conn *net.UnixConn, d time.Duration, fn func()) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(d)))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	fn()
}

// stat performs a STAT round trip and returns the device and block size.
func stat(t *testing.T, conn *net.UnixConn) (uint64, uint32) {
	t.Helper()
	send(t, conn, msgStat, nil)
	var h header
	var payload []byte
	var fds []int
	withReadDeadline(t, conn, faultDeadline, func() { h, payload, fds = readFrame(t, conn) })
	require.Equal(t, uint16(msgStatResponse), h.msgType)
	require.Empty(t, fds)
	require.Len(t, payload, statResponseSize)
	return binary.LittleEndian.Uint64(payload[0:8]), binary.LittleEndian.Uint32(payload[8:12])
}

// fetch performs a FETCH of [off, off+length) on a session of its own.
func fetch(t *testing.T, socket string, off, length uint64) ([]deviceRange, []int) {
	t.Helper()
	conn := dial(t, socket)
	defer func() { _ = conn.Close() }()
	send(t, conn, msgFetch, encodeRange(off, length))
	var ranges []deviceRange
	var fds []int
	withReadDeadline(t, conn, caseDeadline, func() { ranges, fds, _ = readRangeResponse(t, conn) })
	return ranges, fds
}

// deviceBytes assembles the device bytes of [off, off+length) from a FETCH:
// data ranges are read from their backing fds, /dev/zero ranges and
// anything past a backing file's EOF read as zero. It is the reference
// fault-populated memory is compared with.
func deviceBytes(t *testing.T, socket string, off, length uint64) []byte {
	t.Helper()
	ranges, fds := fetch(t, socket, off, length)
	defer closeFds(fds)
	buf := make([]byte, length)
	for i, r := range ranges {
		require.GreaterOrEqual(t, r.deviceOffset, off, "range before the requested window")
		require.LessOrEqual(t, r.deviceOffset+r.length, off+length, "range beyond the requested window")
		if isZeroDevice(t, fds[i]) {
			continue
		}
		dst := buf[r.deviceOffset-off : r.deviceOffset-off+r.length]
		for done := 0; done < len(dst); {
			n, err := unix.Pread(fds[i], dst[done:], int64(r.fileOffset)+int64(done))
			require.NoError(t, err, "pread backing fd")
			if n == 0 {
				break
			}
			done += n
		}
	}
	return buf
}

func isZeroDevice(t *testing.T, fd int) bool {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &st))
	return st.Mode&unix.S_IFMT == unix.S_IFCHR
}

// requireSameBytes compares two device views and reports the first wrong
// offset and the number of wrong bytes.
func requireSameBytes(t *testing.T, want, got []byte, desc string) {
	t.Helper()
	require.Len(t, got, len(want), "%s: length", desc)
	if bytes.Equal(want, got) {
		return
	}
	first, wrong := -1, 0
	for i := range want {
		if want[i] != got[i] {
			if first < 0 {
				first = i
			}
			wrong++
		}
	}
	t.Fatalf("%s: %d wrong bytes, first at device offset %#x (want %#02x, got %#02x)", desc, wrong, first, want[first], got[first])
}

// requireFailsClosed asserts the service ends the session within the
// deadline without sending anything.
func requireFailsClosed(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(faultDeadline)))
	n, err := conn.Read(make([]byte, 1))
	require.Error(t, err, "expected the session to fail closed, got %d response byte(s)", n)
	require.False(t, os.IsTimeout(err), "service neither answered nor closed the session (hang)")
}

// requireAlive asserts the service still answers a fresh session.
func requireAlive(t *testing.T, s *service, wantSize uint64) {
	t.Helper()
	require.Equal(t, wantSize, s.deviceSize(t))
}

func alignUp(v, a uint64) uint64   { return (v + a - 1) / a * a }
func alignDown(v, a uint64) uint64 { return v / a * a }

// faultClient owns an anonymous VMA covering the device, registered with a
// real userfaultfd that was handed to the service in the HANDSHAKE.
type faultClient struct {
	conn       *net.UnixConn
	uffd       int
	mem        []byte
	deviceSize uint64
	blockSize  uint32
	faultSize  uint64
	region     vmaRegion
	touchers   sync.WaitGroup
	closeOnce  sync.Once
}

// newFaultClient maps and registers the VMA and performs the HANDSHAKE.
// regionSize 0 declares the whole device.
func newFaultClient(t *testing.T, s *service, flags byte, faultSize, regionSize uint64) *faultClient {
	t.Helper()
	conn := dial(t, s.socket)
	deviceSize, blockSize := stat(t, conn)
	require.Positive(t, deviceSize)

	mem, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	require.NoError(t, err, "anonymous VMA mmap")
	uffd, err := newUserfaultfd()
	require.NoError(t, err)
	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	require.NoError(t, registerMissing(uffd, base, deviceSize))

	if regionSize == 0 {
		regionSize = deviceSize
	}
	c := &faultClient{
		conn:       conn,
		uffd:       uffd,
		mem:        mem,
		deviceSize: deviceSize,
		blockSize:  blockSize,
		faultSize:  faultSize,
		region: vmaRegion{
			virtAddr:  base,
			size:      regionSize,
			faultSize: faultSize,
			prot:      int32(unix.PROT_READ | unix.PROT_WRITE),
			flags:     int32(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
		},
	}
	t.Cleanup(func() { c.close(t) })

	frame := encodeHandshake(protocolVersion, flags, []vmaRegion{c.region})
	rights := unix.UnixRights(uffd)
	n, oobn, err := conn.WriteMsgUnix(frame, rights, nil)
	require.NoError(t, err, "HANDSHAKE send")
	require.Equal(t, len(frame), n)
	require.Equal(t, len(rights), oobn)
	return c
}

// close tears the client down in an order that can neither crash nor hang
// the test binary: drop the session so the service releases its copy of
// the userfaultfd, close ours so pending faults resolve as anonymous zero
// pages, wait for the touchers, then unmap the VMA.
func (c *faultClient) close(t *testing.T) {
	t.Helper()
	c.closeOnce.Do(func() {
		_ = c.conn.Close()
		_ = unix.Close(c.uffd)
		done := make(chan struct{})
		go func() { c.touchers.Wait(); close(done) }()
		select {
		case <-done:
			require.NoError(t, unix.Munmap(c.mem))
		case <-time.After(caseDeadline):
			// A blocked toucher would fault on an unmapped VMA: leak it.
			t.Errorf("touchers still blocked %v after every userfaultfd was closed; leaking the VMA", caseDeadline)
		}
	})
}

// ack proves the HANDSHAKE was accepted: a rejected one ends the session,
// so this STAT would fail.
func (c *faultClient) ack(t *testing.T) {
	t.Helper()
	size, _ := stat(t, c.conn)
	require.Equal(t, c.deviceSize, size)
}

// touchAsync faults mem[off] in on its own goroutine and delivers the byte.
// It reads through process_vm_readv(2) on this process rather than a plain
// load: the kernel resolves the missing page through the same userfaultfd,
// but the Go runtime sees a goroutine in a syscall, so a stop-the-world
// (a GC triggered elsewhere) completes while the fault is outstanding. A
// plain load would wedge its thread at a non-preemptible fault and deadlock
// any test that serves its own faults in-process (zerocopy).
func (c *faultClient) touchAsync(t *testing.T, off uint64) <-chan byte {
	ch := make(chan byte, 1)
	c.touchers.Add(1)
	go func() {
		defer c.touchers.Done()
		var b [1]byte
		local := []unix.Iovec{{Base: &b[0], Len: 1}}
		remote := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&c.mem[off])), Len: 1}}
		for {
			n, err := unix.ProcessVMReadv(os.Getpid(), local, remote, 0)
			if err == unix.EINTR {
				continue
			}
			if err != nil || n != 1 {
				t.Errorf("process_vm_readv touch at device offset %#x: n=%d err=%v", off, n, err)
				return
			}
			break
		}
		ch <- b[0]
	}()
	return ch
}

func waitTouch(t *testing.T, ch <-chan byte, timeout time.Duration, desc string) byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(timeout):
		t.Fatalf("page fault did not complete within %v: %s", timeout, desc)
		return 0
	}
}

// snapshot copies the whole VMA, faulting missing pages in, under a
// deadline.
func (c *faultClient) snapshot(t *testing.T, desc string) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	c.touchers.Add(1)
	go func() {
		defer c.touchers.Done()
		buf := make([]byte, len(c.mem))
		copy(buf, c.mem)
		ch <- buf
	}()
	select {
	case buf := <-ch:
		return buf
	case <-time.After(caseDeadline):
		t.Fatalf("full device read did not complete within %v: %s", caseDeadline, desc)
		return nil
	}
}

// readRanges reads one RANGE_RESPONSE on the client's session.
func (c *faultClient) readRanges(t *testing.T, timeout time.Duration) ([]deviceRange, []int, int) {
	t.Helper()
	var ranges []deviceRange
	var fds []int
	var frames int
	withReadDeadline(t, c.conn, timeout, func() { ranges, fds, frames = readRangeResponse(t, c.conn) })
	return ranges, fds, frames
}

// serveZerocopyFault resolves one zerocopy fault: it maps the returned
// ranges over the VMA, wakes the faulting range and closes the fds.
func (c *faultClient) serveZerocopyFault(t *testing.T) []deviceRange {
	t.Helper()
	ranges, fds, _ := c.readRanges(t, faultDeadline)
	c.mapRanges(t, ranges, fds, true)
	closeFds(fds)
	return ranges
}

// mapRanges installs ranges over the VMA with MAP_FIXED: data ranges map
// their fd read-only, /dev/zero ranges fresh anonymous pages. With wake the
// covered window is woken with UFFDIO_WAKE afterwards.
func (c *faultClient) mapRanges(t *testing.T, ranges []deviceRange, fds []int, wake bool) {
	t.Helper()
	require.NotEmpty(t, ranges, "fault resolution returned no ranges")
	require.Len(t, fds, len(ranges), "one fd per range")

	pageSize := uint64(unix.Getpagesize())
	lo, hi := ^uint64(0), uint64(0)
	for i, r := range ranges {
		require.GreaterOrEqual(t, r.deviceOffset, c.region.offset, "range below the registered region")
		require.LessOrEqual(t, r.deviceOffset+r.length, c.region.offset+c.region.size, "range beyond the registered region")
		delta := r.deviceOffset - c.region.offset
		lo = min(lo, c.region.virtAddr+delta)
		hi = max(hi, c.region.virtAddr+delta+r.length)
		if isZeroDevice(t, fds[i]) {
			// A hole may start in the partial page of a data tail, which
			// already reads as zero past the backing file's EOF; only the
			// page-aligned part needs a fresh mapping.
			zstart, zend := alignUp(delta, pageSize), alignUp(delta+r.length, pageSize)
			if zstart < zend {
				addr := unsafe.Add(unsafe.Pointer(&c.mem[0]), int(zstart))
				_, err := unix.MmapPtr(-1, 0, addr, uintptr(zend-zstart),
					unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED)
				require.NoError(t, err, "MAP_FIXED zero range at device offset %#x", r.deviceOffset)
			}
			continue
		}
		require.Zero(t, delta%pageSize, "data range device offset must be page aligned")
		require.Zero(t, r.fileOffset%pageSize, "data range file offset must be page aligned")
		addr := unsafe.Add(unsafe.Pointer(&c.mem[0]), int(delta))
		_, err := unix.MmapPtr(fds[i], int64(r.fileOffset), addr, uintptr(r.length), unix.PROT_READ, unix.MAP_PRIVATE|unix.MAP_FIXED)
		require.NoError(t, err, "MAP_FIXED data range at device offset %#x", r.deviceOffset)
	}

	if wake {
		start := alignDown(lo, pageSize)
		arg := uffdioRangeArg{start: start, len: alignUp(hi, pageSize) - start}
		require.NoError(t, uffdIoctl(c.uffd, uffdioWakeIoctl, unsafe.Pointer(&arg)), "UFFDIO_WAKE")
	}
}

// childLog writes one protocol line with a raw write: once the deliberately
// unresolved fault is issued, the child's runtime timers starve, so nothing
// on this path may depend on them.
func childLog(format string, args ...any) {
	_, _ = unix.Write(1, []byte(fmt.Sprintf(format+"\n", args...)))
}

func childFail(format string, args ...any) int {
	_, _ = unix.Write(2, []byte(fmt.Sprintf("ERROR: "+format+"\n", args...)))
	return 1
}

func childEnvUint(name string) (uint64, error) {
	value := os.Getenv(name)
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", name, value, err)
	}
	return n, nil
}

// runOutstandingFaultChild is the child of
// TestLifecycle/DisconnectWithOutstandingFault. It opens a session whose
// HANDSHAKE declares only a prefix of the device, reads outside it, so that
// fault stays outstanding, and on any stdin input tears the session down,
// socket first, then its userfaultfd, so the read must resolve as an
// anonymous zero page.
//
// It prints READY (session live), TOUCHING (just before the outstanding
// read), RESOLVED <byte> (the read completed after teardown) and DONE.
func runOutstandingFaultChild() int {
	socket := os.Getenv(childSocketEnv)
	if socket == "" {
		return childFail("%s not set", childSocketEnv)
	}
	deviceSize, err := childEnvUint(childDeviceSizeEnv)
	if err != nil {
		return childFail("%v", err)
	}
	regionSize, err := childEnvUint(childRegionSizeEnv)
	if err != nil {
		return childFail("%v", err)
	}
	if regionSize == 0 || regionSize >= deviceSize || deviceSize < blockSize {
		return childFail("invalid geometry: device=%d region=%d block=%d", deviceSize, regionSize, blockSize)
	}

	mem, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return childFail("anonymous VMA mmap: %v", err)
	}
	uffd, err := newUserfaultfd()
	if err != nil {
		return childFail("%v", err)
	}
	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	if err := registerMissing(uffd, base, deviceSize); err != nil {
		return childFail("%v", err)
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return childFail("dial %s: %v", socket, err)
	}
	region := vmaRegion{
		virtAddr:  base,
		size:      regionSize,
		faultSize: blockSize,
		prot:      int32(unix.PROT_READ | unix.PROT_WRITE),
		flags:     int32(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
	}
	if _, _, err := conn.WriteMsgUnix(encodeHandshake(protocolVersion, handshakeCopy, []vmaRegion{region}), unix.UnixRights(uffd), nil); err != nil {
		return childFail("HANDSHAKE send: %v", err)
	}
	// Timers still work here: the outstanding fault is not issued yet.
	if err := childStat(conn, deviceSize); err != nil {
		return childFail("post-handshake STAT: %v", err)
	}
	childLog("READY")

	resolved := make(chan byte, 1)
	go func() {
		childLog("TOUCHING")
		resolved <- mem[deviceSize-blockSize]
	}()

	// Any input, or EOF when the parent dies, starts the teardown.
	_, _ = unix.Read(0, make([]byte, 1))
	// With neither userfaultfd copy left, the kernel resolves the blocked
	// read as a plain anonymous fault.
	_ = conn.Close()
	_ = unix.Close(uffd)
	b := <-resolved
	childLog("RESOLVED %d", b)
	if b != 0 {
		return childFail("outstanding fault resolved with byte %#02x, want a zero page", b)
	}
	childLog("DONE")
	return 0
}

// childStat performs one STAT round trip without testing helpers.
func childStat(conn *net.UnixConn, wantSize uint64) error {
	if _, err := conn.Write(encodeHeader(magic, 0, msgStat, 0)); err != nil {
		return fmt.Errorf("send STAT: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(faultDeadline)); err != nil {
		return err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	h := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, h); err != nil {
		return fmt.Errorf("read STAT response header: %w", err)
	}
	if got := binary.LittleEndian.Uint32(h[0:4]); got != magic {
		return fmt.Errorf("bad response magic %#x", got)
	}
	if msgType := binary.LittleEndian.Uint16(h[6:8]); msgType != msgStatResponse {
		return fmt.Errorf("unexpected response type %#x", msgType)
	}
	if n := binary.LittleEndian.Uint32(h[16:20]); n != statResponseSize {
		return fmt.Errorf("unexpected STAT payload length %d", n)
	}
	payload := make([]byte, statResponseSize)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("read STAT response payload: %w", err)
	}
	if size := binary.LittleEndian.Uint64(payload[0:8]); size != wantSize {
		return fmt.Errorf("device size %d, want %d", size, wantSize)
	}
	return nil
}
