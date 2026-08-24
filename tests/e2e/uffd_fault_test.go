// Real userfaultfd integration suite for the nydus UFFD service.
//
// This file implements the layered UFFD CI gate on top of the stateless
// socket smoke in uffd_test.go:
//
//	C1 TestUffdCapabilityPreflight  runner userfaultfd capability preflight;
//	   fails (never skips) when NYDUSFS_UFFD_REQUIRE is set
//	C2 TestUffdRealFaultCopy        managed-copy fault completion: anonymous
//	   VMA + real userfaultfd, cold/warm byte equality, EROFS superblock
//	   check, tail zero pages, and a loop-mounted EROFS whole-tree diff
//	   against the source corpus
//	C3 TestUffdRealFaultZeropage    managed zero-page completion for the
//	   device tail hole backed by /dev/zero
//	C4 TestUffdRealFaultZerocopy    zerocopy fault completion: RANGE_RESPONSE
//	   FDs, fixed mappings and UFFDIO_WAKE driven by the client
//	C5 TestUffdPrefaultAndBatching  handshake prefault plus multi-batch
//	   RANGE_RESPONSE coverage on a merged multi-blob image
//	C6 TestUffdNegativeProtocol     malformed/unsupported input fails closed
//	   without hanging or returning success-shaped responses
//	C7 TestUffdBackendFailure       backend corruption fails closed with zero
//	   wrong bytes
//	C8 TestUffdLifecycle            disconnect/stop/restart with outstanding
//	   faults, bounded cleanup, no stale socket reuse
//
// Every fault has an explicit deadline; no case may hang the suite. When a
// case fails and NYDUSFS_UFFD_EVIDENCE_DIR is set, structured diagnostic
// evidence (service log, runner metadata, exit status) is written for CI to
// upload.
package e2e

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
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
	"testing"
	"time"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	uffdMsgHandshake = 0x01

	uffdProtocolVersion       = 1
	uffdHandshakeFlagCopy     = 0x01
	uffdHandshakeFlagPrefault = 0x02
	uffdRegionSize            = 40
	uffdMaxRangesPerMsg       = 16

	// A single fault must complete within this deadline (PRD FR-03) and any
	// failing case must terminate within the case deadline (PRD FR-06).
	uffdFaultDeadline = 10 * time.Second
	uffdCaseDeadline  = 30 * time.Second

	// Linux userfaultfd ABI, matching nydus/src/uffd/core.rs.
	uffdioAPIIoctl      = 0xc018aa3f // UFFDIO_API
	uffdioRegisterIoctl = 0xc020aa00 // UFFDIO_REGISTER
	uffdioWakeIoctl     = 0x8010aa02 // UFFDIO_WAKE
	uffdAPIVersion      = 0xAA
	uffdRegisterMissing = 0x1 // UFFDIO_REGISTER_MODE_MISSING

	// _UFFDIO_* bits reported in uffdio_register.ioctls.
	uffdioBitWake     = 1 << 0x02
	uffdioBitCopy     = 1 << 0x03
	uffdioBitZeropage = 1 << 0x04
)

// Child-process helper environment, used by the outstanding-fault lifecycle
// case: an unresolved userfaultfd fault blocks its thread inside the kernel
// and starves the Go runtime's timers in that process, so the outstanding
// fault must live in a child process the test can observe and tear down from
// outside.
const (
	uffdChildModeEnv              = "NYDUSFS_UFFD_CHILD_MODE"
	uffdChildModeOutstandingFault = "outstanding-fault"
	uffdChildSocketEnv            = "NYDUSFS_UFFD_CHILD_SOCKET"
	uffdChildDeviceSizeEnv        = "NYDUSFS_UFFD_CHILD_DEVICE_SIZE"
	uffdChildBlockSizeEnv         = "NYDUSFS_UFFD_CHILD_BLOCK_SIZE"
	uffdChildRegionSizeEnv        = "NYDUSFS_UFFD_CHILD_REGION_SIZE"
)

// TestMain intercepts the child-helper re-exec of this test binary before any
// test runs; a normal invocation falls through to m.Run.
func TestMain(m *testing.M) {
	if os.Getenv(uffdChildModeEnv) == uffdChildModeOutstandingFault {
		os.Exit(runUffdOutstandingFaultChild())
	}
	os.Exit(m.Run())
}

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

type uffdVmaRegion struct {
	virtAddr  uint64
	size      uint64
	offset    uint64
	faultSize uint64
	prot      int32
	flags     int32
}

func uffdIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// probeUffdCapability explicitly checks every userfaultfd capability the
// suite depends on: the syscall itself, the UFFDIO_API handshake, MISSING-mode
// registration and the UFFDIO_COPY/ZEROPAGE/WAKE ioctls (PRD FR-02).
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

	pageSize := unix.Getpagesize()
	mem, err := unix.Mmap(-1, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("anonymous mmap failed: %v", err)
	}
	defer func() { _ = unix.Munmap(mem) }()

	reg := uffdioRegisterArg{
		rng:  uffdioRangeArg{start: uint64(uintptr(unsafe.Pointer(&mem[0]))), len: uint64(pageSize)},
		mode: uffdRegisterMissing,
	}
	if err := uffdIoctl(fd, uffdioRegisterIoctl, unsafe.Pointer(&reg)); err != nil {
		return fmt.Errorf("UFFDIO_REGISTER (MISSING mode) failed: %v", err)
	}
	const required = uffdioBitWake | uffdioBitCopy | uffdioBitZeropage
	if reg.ioctls&required != required {
		return fmt.Errorf("required UFFD ioctls missing: have %#x, need WAKE|COPY|ZEROPAGE (%#x)", reg.ioctls, uint64(required))
	}
	return nil
}

// uffdCapabilityRequired reports whether missing runner capability must fail
// the suite instead of skipping it. CI sets NYDUSFS_UFFD_REQUIRE=1 so the
// gate can never be silently skipped (PRD FR-02, M-02).
func uffdCapabilityRequired() bool {
	return os.Getenv("NYDUSFS_UFFD_REQUIRE") != ""
}

func requireUffdRunner(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		if uffdCapabilityRequired() {
			t.Fatal("unsupported-runner: UFFD tests require Linux and NYDUSFS_UFFD_REQUIRE forbids skipping")
		}
		t.Skip("UFFD tests require Linux")
	}
	if err := probeUffdCapability(); err != nil {
		if uffdCapabilityRequired() {
			t.Fatalf("unsupported-runner: %v (NYDUSFS_UFFD_REQUIRE forbids skipping)", err)
		}
		t.Skipf("skipping: %v (set NYDUSFS_UFFD_REQUIRE=1 to fail instead)", err)
	}
}

// TestUffdCapabilityPreflight is the explicit runner preflight (V-UFFD-CAP):
// it verifies the userfaultfd syscall, the UFFDIO_API handshake, MISSING-mode
// registration and the required ioctls before any integration case runs. With
// NYDUSFS_UFFD_REQUIRE set it fails closed instead of skipping.
func TestUffdCapabilityPreflight(t *testing.T) {
	if runtime.GOOS != "linux" {
		if uffdCapabilityRequired() {
			t.Fatal("unsupported-runner: UFFD capability preflight requires Linux")
		}
		t.Skip("UFFD capability preflight requires Linux")
	}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		t.Logf("runner kernel: %s %s", unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Version[:]))
	}
	if data, err := os.ReadFile("/proc/sys/vm/unprivileged_userfaultfd"); err == nil {
		t.Logf("vm.unprivileged_userfaultfd=%s euid=%d", strings.TrimSpace(string(data)), os.Geteuid())
	}

	if err := probeUffdCapability(); err != nil {
		if uffdCapabilityRequired() {
			t.Fatalf("unsupported-runner: %v", err)
		}
		t.Skipf("runner lacks userfaultfd capability: %v", err)
	}
	t.Log("userfaultfd syscall, UFFDIO_API, MISSING-mode REGISTER and WAKE/COPY/ZEROPAGE ioctls all available")
}

// uffdFixture is one nydus image plus a running `nydus uffd` service.
type uffdFixture struct {
	nydusBin      string
	tmpDir        string
	corpusDir     string
	bootstrapPath string
	blobDir       string
	cacheDir      string
	socketPath    string
	logDir        string
	configPath    string
	blobPaths     []string
	service       *uffdServiceProc
}

type uffdFixtureOpts struct {
	// blobCount > 1 builds a merged multi-blob image (one blob per layer) so
	// FETCH/PROBE/prefault produce more than uffdMaxRangesPerMsg ranges and
	// force multi-batch RANGE_RESPONSE framing.
	blobCount int
	// beforeStart mutates the fixture (e.g. corrupts backend blobs) after the
	// image is built but before the service starts.
	beforeStart func(t *testing.T, f *uffdFixture)
}

func newUffdFixture(t *testing.T, opts uffdFixtureOpts) *uffdFixture {
	t.Helper()
	nydusBin := mustLookupExecutable(t, "nydus")
	if out, err := exec.Command(nydusBin, "uffd", "--help").CombinedOutput(); err != nil {
		if uffdCapabilityRequired() {
			t.Fatalf("nydus binary does not include the uffd subcommand; build with FEATURES=cli,uffd: %s", out)
		}
		t.Skipf("nydus binary does not include the uffd subcommand; build with FEATURES=cli,uffd: %s", out)
	}

	tmpDir := t.TempDir()
	f := &uffdFixture{
		nydusBin:      nydusBin,
		tmpDir:        tmpDir,
		corpusDir:     filepath.Join(tmpDir, "corpus"),
		bootstrapPath: filepath.Join(tmpDir, "image.boot"),
		blobDir:       filepath.Join(tmpDir, "blobs"),
		cacheDir:      filepath.Join(tmpDir, "cache"),
		socketPath:    filepath.Join(tmpDir, "uffd.sock"),
		logDir:        filepath.Join(tmpDir, "logs"),
		configPath:    filepath.Join(tmpDir, "config.yaml"),
	}
	registerUffdEvidence(t, f)

	if opts.blobCount <= 1 {
		corpus.MakeStandardCorpus(t, f.corpusDir)
		f.blobPaths = append(f.blobPaths,
			buildNydusFSImageToDir(t, nydusBin, f.bootstrapPath, f.blobDir, f.corpusDir, uffdSmokeRequestBlock))
	} else {
		for i := 0; i < opts.blobCount; i++ {
			layerDir := filepath.Join(tmpDir, fmt.Sprintf("layer-%02d", i))
			layer := corpus.NewCorpus(t, layerDir)
			data := bytes.Repeat([]byte{byte(i + 1)}, 8192+i*512)
			layer.CreateFile(t, fmt.Sprintf("layer-%02d.bin", i), data)
			f.blobPaths = append(f.blobPaths,
				buildNydusFSImageToDir(t, nydusBin, "", f.blobDir, layerDir, uffdSmokeRequestBlock))
		}
		// `nydus merge` derives each layer's blob ID from its sha256-hex
		// file name, so the merge sources are the blob files themselves
		// (each carries its embedded bootstrap), not separate .boot files.
		mergeNydusBootstrap(t, nydusBin, f.bootstrapPath, f.blobPaths...)
	}
	writeLocalStorageConfig(t, f.configPath, f.blobDir, f.cacheDir)

	if opts.beforeStart != nil {
		opts.beforeStart(t, f)
	}

	f.start(t)
	return f
}

func (f *uffdFixture) start(t *testing.T) {
	t.Helper()
	f.service = startUffdService(t, f.nydusBin, f.bootstrapPath, f.configPath, f.socketPath, f.logDir)
	t.Cleanup(func() { stopUffdService(t, f.service) })
}

// registerUffdEvidence writes structured failure evidence (PRD FR-14) into
// NYDUSFS_UFFD_EVIDENCE_DIR when the test fails: case ID, commit, runner
// kernel, capability state, service exit status, FD summary and the service
// output/log files.
func registerUffdEvidence(t *testing.T, f *uffdFixture) {
	t.Helper()
	evidenceRoot := os.Getenv("NYDUSFS_UFFD_EVIDENCE_DIR")
	if evidenceRoot == "" {
		return
	}
	caseID := t.Name()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		caseDir := filepath.Join(evidenceRoot, strings.ReplaceAll(caseID, "/", "_"))
		if err := os.MkdirAll(caseDir, 0755); err != nil {
			t.Logf("evidence: cannot create %s: %v", caseDir, err)
			return
		}

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
		if svc := f.service; svc != nil {
			if svc.cmd.Process != nil {
				meta["service_pid"] = svc.cmd.Process.Pid
			}
			if svc.cmd.ProcessState != nil {
				meta["service_exit"] = svc.cmd.ProcessState.String()
			} else {
				meta["service_exit"] = "running-at-cleanup"
			}
			_ = os.WriteFile(filepath.Join(caseDir, "service-output.log"), svc.output.Bytes(), 0644)
		}
		if encoded, err := json.MarshalIndent(meta, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(caseDir, "meta.json"), encoded, 0644)
		}
		if entries, err := os.ReadDir(f.logDir); err == nil {
			for _, entry := range entries {
				if entry.Type().IsRegular() {
					data := readFileOrEmpty(filepath.Join(f.logDir, entry.Name()))
					_ = os.WriteFile(filepath.Join(caseDir, "service-"+entry.Name()), data, 0644)
				}
			}
		}
		t.Logf("evidence written to %s", caseDir)
	})
}

// statUffdDevice performs a STAT round trip and returns the device size and
// block size.
func statUffdDevice(t *testing.T, conn *net.UnixConn) (uint64, uint32) {
	t.Helper()
	sendUffdRequest(t, conn, uffdMsgStatRequest, nil)
	header, payload, fds := readUffdFrame(t, conn)
	require.Equal(t, uint16(uffdMsgStatResponse), header.msgType)
	require.Empty(t, fds)
	require.Len(t, payload, uffdStatResponseSize)
	return binary.LittleEndian.Uint64(payload[0:8]), binary.LittleEndian.Uint32(payload[8:12])
}

// fetchUffdDeviceBytes assembles the expected device bytes for
// [off, off+length) through a dedicated FETCH connection: data ranges are
// pread from the returned backing FDs, /dev/zero ranges and everything past a
// backing file's EOF read as zero. This is the reference the fault-populated
// memory is compared against.
func fetchUffdDeviceBytes(t *testing.T, socketPath string, off, length uint64) []byte {
	t.Helper()
	conn := dialUffdSocket(t, socketPath)
	defer func() { require.NoError(t, conn.Close()) }()

	sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(off, length))
	var ranges []uffdRange
	var fds []int
	withUffdReadDeadline(t, conn, uffdCaseDeadline, func() {
		ranges, fds, _ = readUffdRangeResponses(t, conn)
	})
	defer closeRawFds(fds)
	require.Len(t, fds, len(ranges))

	buf := make([]byte, length)
	for i, r := range ranges {
		require.GreaterOrEqual(t, r.deviceOffset, off, "range before requested window")
		require.LessOrEqual(t, r.deviceOffset+r.length, off+length, "range beyond requested window")
		if uffdFdIsZeroDevice(t, fds[i]) {
			continue // stays zero
		}
		dst := buf[r.deviceOffset-off : r.deviceOffset-off+r.length]
		preadIntoBuffer(t, fds[i], dst, int64(r.fileOffset))
	}
	return buf
}

// preadIntoBuffer fills dst from fd starting at off; bytes past EOF stay
// zero, matching sparse device semantics.
func preadIntoBuffer(t *testing.T, fd int, dst []byte, off int64) {
	t.Helper()
	total := 0
	for total < len(dst) {
		n, err := unix.Pread(fd, dst[total:], off+int64(total))
		require.NoError(t, err, "pread backing fd")
		if n == 0 {
			return // EOF: remainder reads as zero
		}
		total += n
	}
}

func uffdFdIsZeroDevice(t *testing.T, fd int) bool {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &st))
	return st.Mode&unix.S_IFMT == unix.S_IFCHR
}

func withUffdReadDeadline(t *testing.T, conn *net.UnixConn, d time.Duration, fn func()) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(d)))
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()
	fn()
}

// uffdFaultClient owns one anonymous VMA registered with a real userfaultfd
// whose fd has been handed to the nydus UFFD service via HANDSHAKE.
type uffdFaultClient struct {
	conn       *net.UnixConn
	uffd       int
	mem        []byte
	deviceSize uint64
	blockSize  uint32
	faultSize  uint64
	region     uffdVmaRegion
	touchers   sync.WaitGroup
	closeOnce  sync.Once
}

// newUffdFaultClient maps an anonymous VMA covering the device, creates and
// registers a real userfaultfd, and performs the HANDSHAKE. regionSize == 0
// registers the full device; a smaller value registers only a prefix so
// faults outside it stay deliberately unresolved (lifecycle tests).
func newUffdFaultClient(t *testing.T, f *uffdFixture, handshakeFlags byte, faultSize, regionSize uint64) *uffdFaultClient {
	t.Helper()
	conn := dialUffdSocket(t, f.socketPath)
	deviceSize, blockSize := statUffdDevice(t, conn)
	require.Greater(t, deviceSize, uint64(0))

	mem, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	require.NoError(t, err, "anonymous VMA mmap")

	rawFd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
	require.Zero(t, errno, "userfaultfd syscall")
	uffd := int(rawFd)

	api := uffdioAPIArg{api: uffdAPIVersion}
	require.NoError(t, uffdIoctl(uffd, uffdioAPIIoctl, unsafe.Pointer(&api)), "UFFDIO_API")

	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	reg := uffdioRegisterArg{
		rng:  uffdioRangeArg{start: base, len: deviceSize},
		mode: uffdRegisterMissing,
	}
	require.NoError(t, uffdIoctl(uffd, uffdioRegisterIoctl, unsafe.Pointer(&reg)), "UFFDIO_REGISTER")
	const required = uffdioBitWake | uffdioBitCopy | uffdioBitZeropage
	require.Equal(t, uint64(required), reg.ioctls&required, "kernel must support WAKE/COPY/ZEROPAGE for the registered VMA")

	if regionSize == 0 {
		regionSize = deviceSize
	}
	c := &uffdFaultClient{
		conn:       conn,
		uffd:       uffd,
		mem:        mem,
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

	frame := encodeUffdHandshakeFrame(uffdProtocolVersion, handshakeFlags, []uffdVmaRegion{c.region})
	n, oobn, err := conn.WriteMsgUnix(frame, unix.UnixRights(uffd), nil)
	require.NoError(t, err, "HANDSHAKE send")
	require.Equal(t, len(frame), n)
	require.Equal(t, len(unix.UnixRights(uffd)), oobn)

	t.Cleanup(func() { c.close(t) })
	return c
}

// close tears the client down in an order that can never SIGSEGV or hang the
// test binary (PRD FR-06): drop the socket so the service releases its
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
		select {
		case <-done:
			require.NoError(t, unix.Munmap(c.mem))
		case <-time.After(uffdCaseDeadline):
			// A blocked toucher would fault on the unmapped VMA; leak the
			// mapping instead of crashing and report the stuck fault.
			t.Errorf("toucher goroutines still blocked %v after closing every userfaultfd; leaking VMA", uffdCaseDeadline)
		}
	})
}

// ack proves the HANDSHAKE was accepted: a rejected handshake terminates the
// connection so the STAT round trip below would fail.
func (c *uffdFaultClient) ack(t *testing.T) {
	t.Helper()
	size, _ := statUffdDevice(t, c.conn)
	require.Equal(t, c.deviceSize, size)
}

// touchAsync faults mem[off] in on a separate goroutine and delivers the
// resolved byte on the channel. The touch reads the byte through
// process_vm_readv(2) on the own process instead of a direct load: the kernel
// resolves the missing page through the same userfaultfd path, but the Go
// runtime sees the goroutine blocked in a syscall, so a concurrent
// stop-the-world (e.g. a GC triggered by an allocation elsewhere in the test)
// completes while the fault is outstanding. A direct load would wedge the OS
// thread at a non-preemptible page fault, and any stop-the-world would then
// deadlock the tests that serve their own faults in-process (zerocopy): the
// serving goroutine blocks in gcStart waiting for the faulting thread, which
// only resumes once the fault it is waiting on gets served.
func (c *uffdFaultClient) touchAsync(t *testing.T, off uint64) <-chan byte {
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

func waitUffdTouch(t *testing.T, ch <-chan byte, timeout time.Duration, desc string) byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(timeout):
		t.Fatalf("page fault did not complete within %v: %s", timeout, desc)
		return 0
	}
}

// snapshotWithDeadline copies the whole VMA (faulting missing pages on
// demand) under a deadline and returns the copy.
func (c *uffdFaultClient) snapshotWithDeadline(t *testing.T, timeout time.Duration, desc string) []byte {
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
	case <-time.After(timeout):
		t.Fatalf("full device read did not complete within %v: %s", timeout, desc)
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

func (c *uffdFaultClient) readRangeBatches(t *testing.T, timeout time.Duration) ([]uffdRange, []int, int) {
	t.Helper()
	var ranges []uffdRange
	var fds []int
	var batches int
	withUffdReadDeadline(t, c.conn, timeout, func() {
		ranges, fds, batches = readUffdRangeResponses(t, c.conn)
	})
	return ranges, fds, batches
}

// mapRanges installs the returned ranges over the anonymous VMA with
// MAP_FIXED: data ranges map the backing FD read-only, /dev/zero ranges map
// fresh anonymous zero pages. When wake is set, the covered window is woken
// with UFFDIO_WAKE afterwards.
func (c *uffdFaultClient) mapRanges(t *testing.T, ranges []uffdRange, fds []int, wake bool) {
	t.Helper()
	require.NotEmpty(t, ranges, "fault resolution returned no ranges")
	require.Len(t, fds, len(ranges), "SCM_RIGHTS FD count must match range count")

	pageSize := uint64(unix.Getpagesize())
	var lo, hi uint64
	lo = ^uint64(0)
	for i, r := range ranges {
		require.GreaterOrEqual(t, r.deviceOffset, c.region.offset, "range below registered region")
		require.LessOrEqual(t, r.deviceOffset+r.length, c.region.offset+c.region.size, "range beyond registered region")
		delta := r.deviceOffset - c.region.offset
		vstart := c.region.virtAddr + delta
		vend := vstart + r.length
		if vstart < lo {
			lo = vstart
		}
		if vend > hi {
			hi = vend
		}
		if uffdFdIsZeroDevice(t, fds[i]) {
			// Zero holes start after (possibly unaligned) data tails whose
			// partial page already reads as zero past the backing file EOF,
			// so only the page-aligned part needs a fresh anonymous mapping.
			zstart := alignUpUint64(delta, pageSize)
			zend := alignUpUint64(delta+r.length, pageSize)
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
		_, err := unix.MmapPtr(fds[i], int64(r.fileOffset), addr, uintptr(r.length),
			unix.PROT_READ, unix.MAP_PRIVATE|unix.MAP_FIXED)
		require.NoError(t, err, "MAP_FIXED data range at device offset %#x", r.deviceOffset)
	}

	if wake {
		start := alignDownUint64(lo, pageSize)
		arg := uffdioRangeArg{start: start, len: alignUpUint64(hi, pageSize) - start}
		require.NoError(t, uffdIoctl(c.uffd, uffdioWakeIoctl, unsafe.Pointer(&arg)), "UFFDIO_WAKE")
	}
}

func alignUpUint64(v, a uint64) uint64 {
	return (v + a - 1) / a * a
}

func alignDownUint64(v, a uint64) uint64 {
	return v / a * a
}

func encodeUffdHandshakeFrame(version uint16, flags byte, regions []uffdVmaRegion) []byte {
	payloadLen := 4 + len(regions)*uffdRegionSize
	frame := make([]byte, uffdHeaderSize+payloadLen)
	binary.LittleEndian.PutUint32(frame[0:4], uffdMagic)
	binary.LittleEndian.PutUint16(frame[6:8], uffdMsgHandshake)
	binary.LittleEndian.PutUint32(frame[16:20], uint32(payloadLen))
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
		off += uffdRegionSize
	}
	return frame
}

// requireSameUffdBytes compares two device views and reports the first
// mismatching offset plus the total number of wrong bytes so a failure can be
// located precisely (PRD NFR-01, NFR-03).
func requireSameUffdBytes(t *testing.T, expected, got []byte, desc string) {
	t.Helper()
	require.Len(t, got, len(expected), "%s: length mismatch", desc)
	if bytes.Equal(expected, got) {
		return
	}
	first := -1
	wrong := 0
	for i := range expected {
		if expected[i] != got[i] {
			if first < 0 {
				first = i
			}
			wrong++
		}
	}
	t.Fatalf("%s: %d wrong bytes, first mismatch at device offset %#x (expected %#02x, got %#02x)",
		desc, wrong, first, expected[first], got[first])
}

func uffdErofsSupported() bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "\terofs\n")
}

// TestUffdRealFaultCopy verifies managed-copy fault completion
// (V-UFFD-REAL-FAULT / V-UFFD-COLD-WARM): a real userfaultfd plus anonymous
// VMA is handed to the service, cold reads block until the service resolves
// them with UFFDIO_COPY/UFFDIO_ZEROPAGE, and the populated memory is compared
// byte-for-byte against the device reference, the EROFS superblock and — when
// the runner supports it — a loop-mounted EROFS whole-tree diff against the
// source corpus.
func TestUffdRealFaultCopy(t *testing.T) {
	requireUffdRunner(t)
	f := newUffdFixture(t, uffdFixtureOpts{})

	c := newUffdFaultClient(t, f, uffdHandshakeFlagCopy, 2*1024*1024, 0)
	c.ack(t)

	expected := fetchUffdDeviceBytes(t, f.socketPath, 0, c.deviceSize)
	require.Equal(t, uint32(erofsSuperMagic), binary.LittleEndian.Uint32(expected[erofsSuperOffset:erofsSuperOffset+4]),
		"device reference must carry the EROFS superblock magic")

	// Cold: the very first fault must complete within the single-fault
	// deadline and return the right byte.
	first := waitUffdTouch(t, c.touchAsync(t, 0), uffdFaultDeadline, "cold fault at device offset 0")
	require.Equal(t, expected[0], first, "cold fault returned a wrong byte")

	// Touch every fault window under an explicit per-fault deadline, then
	// snapshot the whole device.
	for off := uint64(0); off < c.deviceSize; off += c.faultSize {
		waitUffdTouch(t, c.touchAsync(t, off), uffdFaultDeadline, fmt.Sprintf("cold fault at device offset %#x", off))
	}
	cold := c.snapshotWithDeadline(t, uffdCaseDeadline, "cold full-device read")
	requireSameUffdBytes(t, expected, cold, "cold fault-populated memory vs device reference")
	require.Equal(t, uint32(erofsSuperMagic), binary.LittleEndian.Uint32(cold[erofsSuperOffset:erofsSuperOffset+4]),
		"fault-populated memory must carry the EROFS superblock magic")

	// Device tail past the flattened data must read as zero pages.
	tail := cold[c.deviceSize-uint64(c.blockSize):]
	require.Equal(t, make([]byte, c.blockSize), tail, "device tail must be zero-filled")

	// Warm: repeated reads of the already-resolved pages must be identical
	// and must not need the service (FR-05).
	warm := c.snapshotWithDeadline(t, uffdCaseDeadline, "warm full-device read")
	requireSameUffdBytes(t, expected, warm, "warm repeated read vs device reference")

	// Corpus-level ground truth: the fault-populated memory is a complete
	// EROFS image; loop-mount it and diff the tree against the source corpus.
	if os.Geteuid() != 0 || !uffdErofsSupported() {
		t.Log("skipping loop-mounted EROFS corpus diff (requires root and EROFS kernel support)")
		return
	}
	imgPath := filepath.Join(f.tmpDir, "faulted-device.img")
	require.NoError(t, os.WriteFile(imgPath, cold, 0644))
	mnt := filepath.Join(f.tmpDir, "mnt-erofs")
	require.NoError(t, os.MkdirAll(mnt, 0755))
	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro,loop", imgPath, mnt).CombinedOutput()
	require.NoError(t, err, "failed to loop-mount fault-populated device as erofs: %s", out)
	defer func() {
		if out, err := exec.Command("umount", mnt).CombinedOutput(); err != nil {
			t.Logf("failed to umount %s: %s", mnt, out)
		}
	}()
	roDiffTree(t, f.corpusDir, mnt, true)
}

// TestUffdRealFaultZeropage verifies that a fault in a /dev/zero-backed hole
// (the device tail) completes through the managed zero-page path and reads as
// zeros (V-UFFD-REAL-FAULT zero-hole case).
func TestUffdRealFaultZeropage(t *testing.T) {
	requireUffdRunner(t)
	f := newUffdFixture(t, uffdFixtureOpts{})

	c := newUffdFaultClient(t, f, uffdHandshakeFlagCopy, uint64(uffdSmokeRequestBlock), 0)
	c.ack(t)

	// Locate the tail hole: the last resolved range of the device must be
	// backed by /dev/zero (flattened data is aligned up to the device size).
	conn := dialUffdSocket(t, f.socketPath)
	defer func() { require.NoError(t, conn.Close()) }()
	sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, c.deviceSize))
	var ranges []uffdRange
	var fds []int
	withUffdReadDeadline(t, conn, uffdCaseDeadline, func() {
		ranges, fds, _ = readUffdRangeResponses(t, conn)
	})
	defer closeRawFds(fds)
	require.NotEmpty(t, ranges)
	last := ranges[len(ranges)-1]
	require.True(t, uffdFdIsZeroDevice(t, fds[len(fds)-1]),
		"fixture must expose a /dev/zero tail hole for the zero-page case")
	require.Equal(t, c.deviceSize, last.deviceOffset+last.length, "tail hole must reach the device end")

	target := c.deviceSize - uint64(c.blockSize)
	require.GreaterOrEqual(t, target, last.deviceOffset, "tail block must be inside the zero hole")

	b := waitUffdTouch(t, c.touchAsync(t, target), uffdFaultDeadline, "zero-page fault at device tail")
	require.Zero(t, b, "zero hole must fault in as zero")
	page := c.mem[target : target+uint64(c.blockSize)]
	require.Equal(t, make([]byte, c.blockSize), page, "the whole tail block must be zero after the fault")
}

// TestUffdRealFaultZerocopy verifies zerocopy fault completion
// (V-UFFD-REAL-FAULT zerocopy case): the fault produces RANGE_RESPONSE frames
// with backing FDs, the client installs fixed mappings and wakes the fault
// with UFFDIO_WAKE, and the resumed read observes the right bytes.
func TestUffdRealFaultZerocopy(t *testing.T) {
	requireUffdRunner(t)
	f := newUffdFixture(t, uffdFixtureOpts{})

	faultSize := uint64(64 * 1024)
	c := newUffdFaultClient(t, f, 0 /* zerocopy */, faultSize, 0)
	c.ack(t)

	expected := fetchUffdDeviceBytes(t, f.socketPath, 0, c.deviceSize)

	// Fault 1: non-zero data at device offset 0 (EROFS metadata).
	ch := c.touchAsync(t, 0)
	ranges, _ := c.serveOneZerocopyFault(t)
	require.NotEmpty(t, ranges)
	b := waitUffdTouch(t, ch, uffdFaultDeadline, "zerocopy fault at device offset 0")
	require.Equal(t, expected[0], b)
	requireSameUffdBytes(t, expected[:faultSize], c.mem[:faultSize], "zerocopy-mapped fault window")

	// Fault 2: the device tail hole must map as zero pages.
	tailOff := c.deviceSize - faultSize
	ch = c.touchAsync(t, tailOff)
	_, _ = c.serveOneZerocopyFault(t)
	b = waitUffdTouch(t, ch, uffdFaultDeadline, "zerocopy fault at device tail")
	require.Zero(t, b)
	requireSameUffdBytes(t, expected[tailOff:], c.mem[tailOff:], "zerocopy-mapped tail window")

	// Warm: the fixed mappings stay installed, so repeated reads are stable
	// and need no further service round trip (FR-05).
	requireSameUffdBytes(t, expected[:faultSize], c.mem[:faultSize], "warm re-read of zerocopy fault window")
}

// TestUffdPrefaultAndBatching verifies the HANDSHAKE prefault path and the
// multi-batch RANGE_RESPONSE contract (C-02): a merged multi-blob image warms
// the cache, the prefault response spans more than one batch, and mapping
// every returned range yields a byte-exact device view without any further
// faults.
func TestUffdPrefaultAndBatching(t *testing.T) {
	requireUffdRunner(t)
	f := newUffdFixture(t, uffdFixtureOpts{blobCount: 20})

	// Warm the whole cache so the prefault probe resolves every blob range,
	// and keep the assembled bytes as the reference.
	statConn := dialUffdSocket(t, f.socketPath)
	deviceSize, _ := statUffdDevice(t, statConn)
	require.NoError(t, statConn.Close())
	expected := fetchUffdDeviceBytes(t, f.socketPath, 0, deviceSize)

	c := newUffdFaultClient(t, f, uffdHandshakeFlagPrefault, 2*1024*1024, 0)
	ranges, fds, batches := c.readRangeBatches(t, uffdCaseDeadline)
	defer closeRawFds(fds)
	require.Greater(t, len(ranges), uffdMaxRangesPerMsg,
		"multi-blob fixture must force more ranges than one RANGE_RESPONSE batch carries")
	require.GreaterOrEqual(t, batches, 2, "prefault must span at least two RANGE_RESPONSE batches")
	c.mapRanges(t, ranges, fds, false)
	c.ack(t)

	// The warm prefault covered the whole device, so a full read needs no
	// fault service at all; the deadline catches any uncovered page.
	all := c.snapshotWithDeadline(t, uffdCaseDeadline, "full read of prefault-mapped device")
	requireSameUffdBytes(t, expected, all, "prefault-mapped memory vs device reference")
}

// TestUffdNegativeProtocol drives the malformed/unsupported input corpus
// (V-UFFD-NEGATIVE, FR-07): every invalid frame must fail closed — the
// connection terminates without a success-shaped response and without
// hanging — while the service stays alive for new sessions. Unknown message
// types and unknown header flag bits must be tolerated per the v1 rules.
func TestUffdNegativeProtocol(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("UFFD negative protocol tests require Linux")
	}
	f := newUffdFixture(t, uffdFixtureOpts{})

	probe := dialUffdSocket(t, f.socketPath)
	deviceSize, blockSize := statUffdDevice(t, probe)
	require.NoError(t, probe.Close())

	devNull, err := os.Open("/dev/null")
	require.NoError(t, err)
	defer func() { require.NoError(t, devNull.Close()) }()
	dummyFd := int(devNull.Fd())

	handshakePayload := func(version uint16, regionCount byte, regions int) []byte {
		payload := make([]byte, 4+regions*uffdRegionSize)
		binary.LittleEndian.PutUint16(payload[0:2], version)
		payload[3] = regionCount
		return payload
	}

	closingCases := []struct {
		name string
		send func(t *testing.T, conn *net.UnixConn)
	}{
		{"BadMagic", func(t *testing.T, conn *net.UnixConn) {
			writeRawUffdFrame(t, conn, 0xdeadbeef, 0, uffdMsgStatRequest, 0, nil, nil)
		}},
		{"OversizedPayloadLength", func(t *testing.T, conn *net.UnixConn) {
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgFetchRequest, 1<<20, nil, nil)
		}},
		{"TruncatedPayload", func(t *testing.T, conn *net.UnixConn) {
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgFetchRequest, uffdFetchRequestSize, make([]byte, 8), nil)
			require.NoError(t, conn.CloseWrite())
		}},
		{"HandshakeUnsupportedVersion", func(t *testing.T, conn *net.UnixConn) {
			payload := handshakePayload(uffdProtocolVersion+1, 0, 0)
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, []int{dummyFd})
		}},
		{"HandshakeMissingFd", func(t *testing.T, conn *net.UnixConn) {
			payload := handshakePayload(uffdProtocolVersion, 0, 0)
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, nil)
		}},
		{"HandshakeExtraFds", func(t *testing.T, conn *net.UnixConn) {
			payload := handshakePayload(uffdProtocolVersion, 0, 0)
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, []int{dummyFd, dummyFd})
		}},
		{"HandshakeMalformedRegions", func(t *testing.T, conn *net.UnixConn) {
			// region_count says one region but no region bytes follow.
			payload := handshakePayload(uffdProtocolVersion, 1, 0)
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgHandshake, uint32(len(payload)), payload, []int{dummyFd})
		}},
		{"StatWithPayload", func(t *testing.T, conn *net.UnixConn) {
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgStatRequest, 4, make([]byte, 4), nil)
		}},
		{"StatWithUnexpectedFd", func(t *testing.T, conn *net.UnixConn) {
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgStatRequest, 0, nil, []int{dummyFd})
		}},
		{"FetchWithUnexpectedFd", func(t *testing.T, conn *net.UnixConn) {
			payload := encodeUffdDeviceRange(0, uint64(blockSize))
			writeRawUffdFrame(t, conn, uffdMagic, 0, uffdMsgFetchRequest, uint32(len(payload)), payload, []int{dummyFd})
		}},
		{"FetchZeroLength", func(t *testing.T, conn *net.UnixConn) {
			sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, 0))
		}},
		{"FetchUnaligned", func(t *testing.T, conn *net.UnixConn) {
			sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(123, uint64(blockSize)))
		}},
		{"FetchOutOfBounds", func(t *testing.T, conn *net.UnixConn) {
			sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(deviceSize, uint64(blockSize)))
		}},
		{"FetchOffsetOverflow", func(t *testing.T, conn *net.UnixConn) {
			overflow := ^uint64(0) - uint64(blockSize) + 1
			sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(overflow, 2*uint64(blockSize)))
		}},
	}

	for _, tc := range closingCases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialUffdSocket(t, f.socketPath)
			defer func() { _ = conn.Close() }()
			tc.send(t, conn)
			requireUffdConnFailsClosed(t, conn)
			requireUffdServiceAlive(t, f.socketPath, deviceSize)
		})
	}

	t.Run("UnknownMessageTypeIgnored", func(t *testing.T) {
		// v1 forward compatibility: unknown message types are logged and
		// ignored; the connection keeps working.
		conn := dialUffdSocket(t, f.socketPath)
		defer func() { require.NoError(t, conn.Close()) }()
		writeRawUffdFrame(t, conn, uffdMagic, 0, 0x55, 0, nil, nil)
		size, _ := statUffdDevice(t, conn)
		require.Equal(t, deviceSize, size)
	})

	t.Run("UnknownHeaderFlagsIgnored", func(t *testing.T) {
		// v1 forward compatibility: unknown header flag bits are ignored.
		conn := dialUffdSocket(t, f.socketPath)
		defer func() { require.NoError(t, conn.Close()) }()
		writeRawUffdFrame(t, conn, uffdMagic, 0x8000, uffdMsgStatRequest, 0, nil, nil)
		withUffdReadDeadline(t, conn, uffdFaultDeadline, func() {
			header, payload, fds := readUffdFrame(t, conn)
			require.Equal(t, uint16(uffdMsgStatResponse), header.msgType)
			require.Empty(t, fds)
			require.Len(t, payload, uffdStatResponseSize)
		})
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
	require.NoError(t, err)
	require.Equal(t, len(frame), n)
	require.Equal(t, len(rights), oobn)
}

// requireUffdConnFailsClosed asserts the fail-closed contract: within the
// deadline the service must terminate the connection without sending any
// success-shaped response and without hanging.
func requireUffdConnFailsClosed(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(uffdFaultDeadline)))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	require.Error(t, err, "expected the connection to fail closed, got %d response byte(s)", n)
	require.False(t, os.IsTimeout(err),
		"service neither responded nor closed the connection within the deadline (hang)")
}

// requireUffdServiceAlive asserts the service survived a poisoned connection
// and still answers a fresh session.
func requireUffdServiceAlive(t *testing.T, socketPath string, wantDeviceSize uint64) {
	t.Helper()
	conn := dialUffdSocket(t, socketPath)
	defer func() { require.NoError(t, conn.Close()) }()
	withUffdReadDeadline(t, conn, uffdFaultDeadline, func() {
		size, _ := statUffdDevice(t, conn)
		require.Equal(t, wantDeviceSize, size)
	})
}

// TestUffdBackendFailure verifies bounded fail-closed behaviour when the
// local backend is corrupted (V-UFFD-BACKEND-FAIL, FR-08): the request
// terminates within its deadline, zero wrong bytes are returned, and the
// service keeps serving new sessions.
func TestUffdBackendFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("UFFD backend failure tests require Linux")
	}

	cases := []struct {
		name    string
		corrupt func(t *testing.T, f *uffdFixture)
	}{
		{"BackendTruncated", func(t *testing.T, f *uffdFixture) {
			for _, blob := range f.blobPaths {
				require.NoError(t, os.Truncate(blob, 1024))
			}
		}},
		{"BackendRemoved", func(t *testing.T, f *uffdFixture) {
			for _, blob := range f.blobPaths {
				require.NoError(t, os.Remove(blob))
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newUffdFixture(t, uffdFixtureOpts{beforeStart: tc.corrupt})

			probe := dialUffdSocket(t, f.socketPath)
			deviceSize, _ := statUffdDevice(t, probe)
			require.NoError(t, probe.Close())

			// A cold FETCH over the whole device must hit the corrupted
			// backend and fail closed: no RANGE_RESPONSE (zero wrong bytes),
			// the connection terminates within the deadline.
			conn := dialUffdSocket(t, f.socketPath)
			defer func() { _ = conn.Close() }()
			sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, deviceSize))
			requireUffdConnFailsClosed(t, conn)

			// The unverified ranges must not have been marked ready: a
			// second cold FETCH fails closed the same way.
			again := dialUffdSocket(t, f.socketPath)
			defer func() { _ = again.Close() }()
			sendUffdRequest(t, again, uffdMsgFetchRequest, encodeUffdDeviceRange(0, deviceSize))
			requireUffdConnFailsClosed(t, again)

			requireUffdServiceAlive(t, f.socketPath, deviceSize)
		})
	}
}

// uffdChildLog writes one protocol line to stdout with a raw write syscall:
// after the deliberately-unresolvable fault is issued the child's Go runtime
// timers are starved, so nothing on this path may depend on them.
func uffdChildLog(format string, args ...any) {
	_, _ = unix.Write(1, []byte(fmt.Sprintf(format+"\n", args...)))
}

func uffdChildFail(format string, args ...any) int {
	_, _ = unix.Write(2, []byte(fmt.Sprintf("ERROR: "+format+"\n", args...)))
	return 1
}

func uffdChildEnvUint(name string) (uint64, error) {
	value := os.Getenv(name)
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", name, value, err)
	}
	return n, nil
}

// runUffdOutstandingFaultChild is the re-exec target for
// TestUffdLifecycle/DisconnectWithOutstandingFault. It opens a session whose
// HANDSHAKE declares only a prefix of the device, issues a read outside that
// declared region (which therefore stays outstanding), and on any stdin input
// tears the session down — socket first, then its userfaultfd copy — so the
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

	mem, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
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
	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	reg := uffdioRegisterArg{
		rng:  uffdioRangeArg{start: base, len: deviceSize},
		mode: uffdRegisterMissing,
	}
	if err := uffdIoctl(uffd, uffdioRegisterIoctl, unsafe.Pointer(&reg)); err != nil {
		return uffdChildFail("UFFDIO_REGISTER: %v", err)
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return uffdChildFail("dial %s: %v", socketPath, err)
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
	// handshake terminates the connection. Timers still work here — the
	// outstanding fault has not been issued yet.
	if err := uffdChildStatCheck(conn, deviceSize); err != nil {
		return uffdChildFail("post-handshake STAT: %v", err)
	}
	uffdChildLog("READY")

	// Issue the deliberately-unresolvable read on its own goroutine. From
	// TOUCHING onward the runtime's timers may be starved, so the rest of
	// this process uses only raw syscalls and channel operations.
	resolved := make(chan byte, 1)
	go func() {
		uffdChildLog("TOUCHING")
		resolved <- mem[deviceSize-blockSize]
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

// uffdChildStatCheck performs one STAT round trip without testing helpers and
// verifies the reported device size.
func uffdChildStatCheck(conn *net.UnixConn, wantDeviceSize uint64) error {
	frame := make([]byte, uffdHeaderSize)
	binary.LittleEndian.PutUint32(frame[0:4], uffdMagic)
	binary.LittleEndian.PutUint16(frame[6:8], uffdMsgStatRequest)
	if _, err := conn.Write(frame); err != nil {
		return fmt.Errorf("send STAT: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(uffdFaultDeadline)); err != nil {
		return err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	header := make([]byte, uffdHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read STAT response header: %w", err)
	}
	if magic := binary.LittleEndian.Uint32(header[0:4]); magic != uffdMagic {
		return fmt.Errorf("bad response magic %#x", magic)
	}
	if msgType := binary.LittleEndian.Uint16(header[6:8]); msgType != uffdMsgStatResponse {
		return fmt.Errorf("unexpected response type %#x", msgType)
	}
	payloadLen := binary.LittleEndian.Uint32(header[16:20])
	if payloadLen != uffdStatResponseSize {
		return fmt.Errorf("unexpected STAT payload length %d", payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("read STAT response payload: %w", err)
	}
	if size := binary.LittleEndian.Uint64(payload[0:8]); size != wantDeviceSize {
		return fmt.Errorf("device size %d, want %d", size, wantDeviceSize)
	}
	return nil
}

// TestUffdLifecycle verifies connection and service lifecycle behaviour
// (V-UFFD-LIFECYCLE / C-03): client disconnect with and without an
// outstanding fault, graceful service stop with an active session, socket
// cleanup, stale-socket takeover and a fresh session after restart.
func TestUffdLifecycle(t *testing.T) {
	requireUffdRunner(t)
	f := newUffdFixture(t, uffdFixtureOpts{})

	probe := dialUffdSocket(t, f.socketPath)
	deviceSize, _ := statUffdDevice(t, probe)
	require.NoError(t, probe.Close())

	t.Run("ClientDisconnect", func(t *testing.T) {
		c := newUffdFaultClient(t, f, uffdHandshakeFlagCopy, uint64(uffdSmokeRequestBlock), 0)
		c.ack(t)
		c.close(t)
		requireUffdServiceAlive(t, f.socketPath, deviceSize)
	})

	t.Run("DisconnectWithOutstandingFault", func(t *testing.T) {
		// The child (re-exec of this binary, see TestMain) declares only the
		// first half of the device in its HANDSHAKE and reads a page in the
		// second half, so that fault stays deliberately outstanding. It runs
		// out of process because an unresolved userfaultfd fault starves the
		// Go runtime timers of the faulting process.
		half := alignDownUint64(deviceSize/2, uint64(uffdSmokeRequestBlock))
		require.Greater(t, half, uint64(0), "device too small to split")

		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			uffdChildModeEnv+"="+uffdChildModeOutstandingFault,
			uffdChildSocketEnv+"="+f.socketPath,
			fmt.Sprintf("%s=%d", uffdChildDeviceSizeEnv, deviceSize),
			fmt.Sprintf("%s=%d", uffdChildBlockSizeEnv, uffdSmokeRequestBlock),
			fmt.Sprintf("%s=%d", uffdChildRegionSizeEnv, half),
		)
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		require.NoError(t, cmd.Start())
		defer func() {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

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
				require.True(t, ok, "child exited before printing %s:\n%s", desc, stderr.String())
				return line
			case <-time.After(uffdCaseDeadline):
				t.Fatalf("timed out waiting for child %s:\n%s", desc, stderr.String())
				return ""
			}
		}

		require.Equal(t, "READY", nextLine("READY"))
		require.Equal(t, "TOUCHING", nextLine("TOUCHING"))

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
		// page — never as wrong data — within the case deadline.
		_, err = io.WriteString(stdin, "close\n")
		require.NoError(t, err)
		require.Equal(t, "RESOLVED 0", nextLine("RESOLVED"))
		require.Equal(t, "DONE", nextLine("DONE"))

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			require.NoError(t, err, "child must exit cleanly:\n%s", stderr.String())
		case <-time.After(uffdCaseDeadline):
			_ = cmd.Process.Kill()
			t.Fatalf("child did not exit within %v of teardown:\n%s", uffdCaseDeadline, stderr.String())
		}
		requireUffdServiceAlive(t, f.socketPath, deviceSize)
	})

	t.Run("ServiceStopWithActiveSession", func(t *testing.T) {
		c := newUffdFaultClient(t, f, uffdHandshakeFlagCopy, uint64(uffdSmokeRequestBlock), 0)
		c.ack(t)

		svc := f.service
		require.NoError(t, svc.cmd.Process.Signal(unix.SIGTERM))
		done := make(chan error, 1)
		go func() { done <- svc.cmd.Wait() }()
		select {
		case err := <-done:
			require.NoError(t, err, "service must exit cleanly on SIGTERM:\n%s", svc.output.String())
		case <-time.After(uffdCaseDeadline):
			_ = svc.cmd.Process.Kill()
			<-done
			t.Fatalf("service did not stop within %v of SIGTERM:\n%s", uffdCaseDeadline, svc.output.String())
		}

		// Graceful stop removes the Unix socket; the client observes EOF.
		_, err := os.Stat(f.socketPath)
		require.True(t, os.IsNotExist(err), "service must remove its socket on shutdown")
		requireUffdConnFailsClosed(t, c.conn)
		c.close(t)
	})

	t.Run("RestartWithStaleSocket", func(t *testing.T) {
		// A leftover socket path must not block a restart, and a fresh
		// session against the restarted service must work (v1 promises new
		// sessions after restart, not transparent reconnect/resume).
		require.NoError(t, os.WriteFile(f.socketPath, nil, 0644))
		f.start(t)

		c := newUffdFaultClient(t, f, uffdHandshakeFlagCopy, uint64(uffdSmokeRequestBlock), 0)
		c.ack(t)
		b := waitUffdTouch(t, c.touchAsync(t, 0), uffdFaultDeadline, "cold fault after service restart")
		expected := fetchUffdDeviceBytes(t, f.socketPath, 0, uint64(uffdSmokeRequestBlock))
		require.Equal(t, expected[0], b, "restarted service must resolve faults for new sessions")
	})
}
