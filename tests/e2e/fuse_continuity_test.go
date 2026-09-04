package e2e

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// heldFileRel is the file kept open across the takeover to prove existing
// fds survive the switch; big enough that its two halves cannot be served
// from a single readahead.
const heldFileRel = "upgrade/held_8m.bin"
const heldFileSize = 8 << 20

// heldFileXattrName keeps the corpus out of the builder's "no inode has
// xattrs" fast path, so the mount serves real xattr requests across a
// takeover instead of declaring xattrs unsupported image-wide.
const heldFileXattrName = "user.continuity"
const heldFileXattrValue = "held-across-takeover"

// stressFileRel is re-opened and re-read continuously across the upgrades to
// prove NEW opens never fail either.
const stressFileRel = "upgrade/stress_64k.bin"
const stressFileSize = 64 << 10

// recoveryHeldFileRel is read through one descriptor kept open across crash
// recovery. Keeping it separate from stress traffic makes cache eviction
// deterministic when trapping a published inflight request.
const recoveryHeldFileRel = "upgrade/recovery-held-64k.bin"

// heldDirRel is the directory whose handle is kept open across the takeover.
// Its size and the deliberately small getdents buffer force many FUSE READDIR
// batches on both sides of process replacement.
const heldDirRel = "upgrade/dirmany"
const heldDirEntries = 1024

// maxUpgradeStall bounds how long any single stress operation may take.
// The pause window is expected to be milliseconds; this is a generous
// ceiling that still catches a hung queue.
const maxUpgradeStall = 20 * time.Second

// Mirrors the pinned fuser InflightJournal header and published slot state so
// a test can trap a request that the daemon read but never answered.
const inflightJournalMagic = "FUSRIFL\x00"
const inflightJournalVersionOffset = 8
const inflightJournalVersion uint32 = 2
const inflightJournalCapacityOffset = 12
const inflightJournalHeaderSize = 16
const inflightJournalSlotSize = 12
const inflightSlotPublished uint32 = 2

// fuseSessionHarness owns the image, mount, Daemon Incarnations, retained
// handles, ongoing I/O, logs, and external continuity assertions for one run.
type fuseSessionHarness struct {
	nydusBin       string
	workDir        string
	sourceDir      string
	blobDir        string
	mntDir         string
	bootstrap      string
	ctlSock        string
	supervisorSock string

	reserveRecovery   func() error
	authorizeRecovery func(int) error
	releaseRecovery   func(int)
}

// daemonIncarnation tracks one spawned `nydus fuse` generation.
type daemonIncarnation struct {
	name    string
	cmd     *exec.Cmd
	exited  chan struct{}
	console string
	logDir  string
}

// spawnDaemonIncarnation starts one `nydus fuse` generation with its output tee'd to a
// per-generation console log, with the given mode flags (e.g. --upgrade).
// Readiness polling stays with the caller: a plain start waits for the
// mountpoint, while an upgrade waits until INFO identifies the new pid.
func (e *fuseSessionHarness) spawnDaemonIncarnation(t *testing.T, name string, extra ...string) *daemonIncarnation {
	t.Helper()
	logDir := filepath.Join(e.workDir, "logs-"+name)
	require.NoError(t, os.MkdirAll(logDir, 0755))

	args := []string{
		"fuse",
		"--bootstrap", e.bootstrap,
		"--blob-dir", e.blobDir,
		"--mountpoint", e.mntDir,
		"--control-socket", e.ctlSock,
		"--log-dir", logDir,
	}
	if e.supervisorSock != "" {
		args = append(args, "--supervisor-socket", e.supervisorSock)
	}
	args = append(args, extra...)

	d := &daemonIncarnation{
		name:    name,
		exited:  make(chan struct{}),
		console: filepath.Join(e.workDir, name+".console.log"),
		logDir:  logDir,
	}
	logFile, err := os.Create(d.console)
	require.NoError(t, err)
	cmd := exec.Command(e.nydusBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	d.cmd = cmd
	go func() { _ = cmd.Wait(); close(d.exited) }()
	_ = logFile.Close()

	t.Cleanup(func() {
		if d.alive() {
			_ = d.cmd.Process.Kill()
			<-d.exited
		}
		if t.Failed() {
			t.Logf("--- %s console log ---\n%s", d.name, d.logCorpus())
		}
	})
	return d
}

func (d *daemonIncarnation) alive() bool {
	select {
	case <-d.exited:
		return false
	default:
		return true
	}
}

// waitExit blocks until the daemon exits or the timeout elapses; it reports
// whether the daemon exited.
func (d *daemonIncarnation) waitExit(timeout time.Duration) bool {
	select {
	case <-d.exited:
		return true
	case <-time.After(timeout):
		return false
	}
}

// logCorpus concatenates the console log and every file-log sink.
func (d *daemonIncarnation) logCorpus() string {
	var b strings.Builder
	b.Write(readFileOrEmpty(d.console))
	entries, _ := os.ReadDir(d.logDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			b.Write(readFileOrEmpty(filepath.Join(d.logDir, entry.Name())))
		}
	}
	return b.String()
}

// mountDevOf returns the st_dev of path. Every FUSE mount gets a fresh
// anonymous device; with the fd handoff the mount never moves, so an
// UNCHANGED st_dev across the upgrade proves the successor adopted the live
// connection instead of stacking a new mount.
func mountDevOf(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Stat(path, &st))
	return st.Dev
}

func (e *fuseSessionHarness) mountIdentity(t *testing.T) uint64 {
	t.Helper()
	return mountDevOf(t, e.mntDir)
}

func (e *fuseSessionHarness) requireMounted(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool { return isMountpoint(e.mntDir) },
		20*time.Second, 200*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireUnmounted(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool { return !isMountpoint(e.mntDir) },
		10*time.Second, 200*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireControlOwner(
	t *testing.T,
	daemon *daemonIncarnation,
	timeout time.Duration,
	interval time.Duration,
	message string,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		pid, err := controlOwnerPID(e.ctlSock)
		return err == nil && pid == uint32(daemon.cmd.Process.Pid)
	}, timeout, interval, message)
}

func (e *fuseSessionHarness) requireServingSession(
	t *testing.T,
	daemon *daemonIncarnation,
	sessionID string,
	timeout time.Duration,
	interval time.Duration,
	message string,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		info, err := requestControlInfo(e.ctlSock)
		return err == nil &&
			info.Info.Pid == uint32(daemon.cmd.Process.Pid) &&
			info.SessionID == sessionID
	}, timeout, interval, message)
}

func (e *fuseSessionHarness) requireControlUnavailable(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := requestControlInfo(e.ctlSock)
		return err != nil
	}, 10*time.Second, 100*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireMountIdentity(
	t *testing.T,
	want uint64,
	message string,
) {
	t.Helper()
	require.Equal(t, want, e.mountIdentity(t), message)
}

func newFuseSessionHarness(t *testing.T) *fuseSessionHarness {
	t.Helper()
	env := &fuseSessionHarness{}
	env.nydusBin = lookupBinFromEnv(t, "NYDUS_BIN", "nydus")
	env.workDir = t.TempDir()
	env.sourceDir = filepath.Join(env.workDir, "source")
	env.blobDir = filepath.Join(env.workDir, "blobs")
	env.mntDir = filepath.Join(env.workDir, "mnt")
	env.bootstrap = filepath.Join(env.workDir, "bootstrap.boot")

	// Keep the control socket out of the test's temp dir: Unix socket paths
	// are capped near 108 bytes and TMPDIR may be redirected into the repo.
	sockDir, err := os.MkdirTemp("", "nydus-upg")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	env.ctlSock = filepath.Join(sockDir, "ctl.sock")
	require.NoError(t, os.MkdirAll(env.sourceDir, 0755))
	require.NoError(t, os.MkdirAll(env.mntDir, 0755))
	t.Cleanup(func() { unmountFuse(env.mntDir) })
	return env
}

// setupFailoverHarness builds the one corpus used by all continuity scenarios.
func setupFailoverHarness(t *testing.T) (*fuseSessionHarness, []byte) {
	t.Helper()
	env := newFuseSessionHarness(t)
	env.supervisorSock = filepath.Join(filepath.Dir(env.ctlSock), "supervisor.sock")
	stressSource := bytes.Repeat([]byte("nydus-failover\n"), stressFileSize/15+1)
	stressSource = stressSource[:stressFileSize]
	stressPath := filepath.Join(env.sourceDir, stressFileRel)
	require.NoError(t, os.MkdirAll(filepath.Dir(stressPath), 0755))
	require.NoError(t, os.WriteFile(stressPath, stressSource, 0644))
	require.NoError(t, os.WriteFile(
		filepath.Join(env.sourceDir, recoveryHeldFileRel),
		stressSource,
		0644,
	))
	heldSource := bytes.Repeat([]byte("nydus-hot-upgrade\n"), heldFileSize/18+1)
	require.NoError(t, os.WriteFile(
		filepath.Join(env.sourceDir, heldFileRel),
		heldSource[:heldFileSize],
		0644,
	))
	dirPath := filepath.Join(env.sourceDir, heldDirRel)
	require.NoError(t, os.MkdirAll(dirPath, 0755))
	for i := 0; i < heldDirEntries; i++ {
		require.NoError(t, os.WriteFile(
			filepath.Join(dirPath, fmt.Sprintf("entry_%04d", i)),
			[]byte{byte(i)},
			0644,
		))
	}
	// The image must carry at least one xattr: the builder stamps
	// EROFS_FEATURE_COMPAT_NYDUS_NO_XATTR on a corpus that has none, and the
	// reader then answers every xattr request with ENOSYS so the kernel stops
	// sending them. The differential would see EOPNOTSUPP from listxattr on
	// the mount and nothing to compare across the takeover.
	require.NoError(t, unix.Setxattr(
		filepath.Join(env.sourceDir, heldFileRel),
		heldFileXattrName,
		[]byte(heldFileXattrValue),
		0,
	))
	buildNydusFSImageToDir(t, env.nydusBin, env.bootstrap, env.blobDir, env.sourceDir, 4096)
	return env, stressSource
}

// ioStress runs a continuous open+read+readdir loop against the mount and
// records every error and the longest single iteration. Zero errors across
// an upgrade is the "zero interruption" contract; the max stall is the
// bounded-pause contract.
type ioStress struct {
	stopCh chan struct{}
	doneCh chan struct{}

	mu       sync.Mutex
	ops      int64
	errs     []string
	maxStall time.Duration
	allowEIO bool

	crashGeneration int64
	eioByCrash      map[int64]int64
}

// startIOStress begins the loop. `want` is the expected byte content of
// stressFileRel.
// readFileRaw reads a whole file via raw syscalls, bypassing the os package.
// os.Open registers every fd with Go's process-global epoll netpoller (on
// Linux even regular files; FUSE implements ->poll, so registration
// succeeds). While the daemon is paused at the handoff boundary, an in-kernel
// FUSE_POLL then blocks holding ep->mtx and wedges the whole netpoller —
// including the unrelated goroutine driving the control socket. Raw fds never
// get a pollDesc, so this loop cannot stall the rest of the test.
func readFileRaw(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var out []byte
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, buf[:n]...)
	}
}

func readAtRaw(fd int, size int) ([]byte, error) {
	out := make([]byte, size)
	offset := 0
	for offset < len(out) {
		n, err := unix.Pread(fd, out[offset:], int64(offset))
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, err
		}
		if n == 0 {
			return out[:offset], nil
		}
		offset += n
	}
	return out, nil
}

// countDirEntriesRaw lists a directory via raw getdents(2) for the same
// netpoller-avoidance reason as readFileRaw.
func countDirEntriesRaw(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	count := 0
	buf := make([]byte, 8192)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return 0, err
		}
		if n == 0 {
			return count, nil
		}
		_, _, names := unix.ParseDirent(buf[:n], -1, nil)
		for _, name := range names {
			if name != "." && name != ".." {
				count++
			}
		}
	}
}

func startIOStress(mntDir string, want []byte) *ioStress {
	return startIOStressWithContract(mntDir, want, false)
}

func startFailoverIOStress(mntDir string, want []byte) *ioStress {
	return startIOStressWithContract(mntDir, want, true)
}

func startIOStressWithContract(mntDir string, want []byte, allowEIO bool) *ioStress {
	s := &ioStress{
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		allowEIO:   allowEIO,
		eioByCrash: make(map[int64]int64),
	}
	filePath := filepath.Join(mntDir, stressFileRel)
	dirPath := filepath.Join(mntDir, heldDirRel)
	go func() {
		defer close(s.doneCh)
		for {
			select {
			case <-s.stopCh:
				return
			default:
			}
			start := time.Now()
			var errs []string
			recordError := func(operation string, err error, startedAtCrash int64) {
				s.mu.Lock()
				defer s.mu.Unlock()
				// EIO: journal recovery errored the request out.
				// ECONNABORTED: the request was in flight on a worker
				// clone queue that died with the crashed daemon.
				if s.allowEIO &&
					(errors.Is(err, unix.EIO) || errors.Is(err, unix.ECONNABORTED)) &&
					s.crashGeneration > startedAtCrash {
					s.eioByCrash[s.crashGeneration]++
					return
				}
				s.errs = append(s.errs, fmt.Sprintf("%s: %v", operation, err))
			}
			// A fresh open+read every iteration: proves NEW opens issued
			// mid-handoff are served, not just pre-upgrade fds.
			readGeneration := s.currentCrashGeneration()
			got, err := readFileRaw(filePath)
			if err != nil {
				recordError("read "+stressFileRel, err, readGeneration)
			} else if !bytes.Equal(want, got) {
				errs = append(errs, fmt.Sprintf("read %s: content mismatch", stressFileRel))
			}
			statGeneration := s.currentCrashGeneration()
			var stat unix.Stat_t
			if err := unix.Stat(filePath, &stat); err != nil {
				recordError("stat "+stressFileRel, err, statGeneration)
			} else if stat.Size != int64(len(want)) {
				errs = append(errs, fmt.Sprintf("stat %s: size %d, want %d",
					stressFileRel, stat.Size, len(want)))
			}
			readdirGeneration := s.currentCrashGeneration()
			entries, err := countDirEntriesRaw(dirPath)
			if err != nil {
				recordError("readdir "+heldDirRel, err, readdirGeneration)
			} else if entries != heldDirEntries {
				errs = append(errs, fmt.Sprintf("readdir %s: %d entries, want %d",
					heldDirRel, entries, heldDirEntries))
			}
			stall := time.Since(start)
			s.mu.Lock()
			s.ops++
			s.errs = append(s.errs, errs...)
			if stall > s.maxStall {
				s.maxStall = stall
			}
			s.mu.Unlock()
		}
	}()
	return s
}

// stop ends the loop and returns (ops, errors, max stall).
func (s *ioStress) stop() (int64, []string, time.Duration) {
	close(s.stopCh)
	<-s.doneCh
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops, s.errs, s.maxStall
}

func (s *ioStress) currentCrashGeneration() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.crashGeneration
}

func (s *ioStress) markCrash() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crashGeneration++
	return s.crashGeneration
}

func (s *ioStress) failoverEIOs() map[int64]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[int64]int64, len(s.eioByCrash))
	for crash, count := range s.eioByCrash {
		result[crash] = count
	}
	return result
}

// partialDirReader drives getdents(2) directly with a small buffer so the
// directory handle is provably read in several batches — some before the
// upgrade, the rest after — instead of being slurped into a userspace cache
// in one call.
type partialDirReader struct {
	fd    int
	names []string
}

func openPartialDirReader(t *testing.T, path string) *partialDirReader {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	r := &partialDirReader{fd: fd}
	t.Cleanup(func() {
		if r.fd >= 0 {
			_ = unix.Close(r.fd)
		}
	})
	return r
}

// readBatch performs one small getdents call and returns whether the
// directory is exhausted.
func (r *partialDirReader) readBatch(t *testing.T) bool {
	t.Helper()
	buf := make([]byte, 512)
	n, err := unix.Getdents(r.fd, buf)
	require.NoError(t, err)
	if n == 0 {
		return true
	}
	_, _, names := unix.ParseDirent(buf[:n], -1, nil)
	for _, name := range names {
		if name != "." && name != ".." {
			r.names = append(r.names, name)
		}
	}
	return false
}

// readRest drains the directory to the end.
func (r *partialDirReader) readRest(t *testing.T) {
	t.Helper()
	for !r.readBatch(t) {
	}
}

func (r *partialDirReader) close() {
	_ = unix.Close(r.fd)
	r.fd = -1
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}

func (e *fuseSessionHarness) spawnRecoveryDaemon(
	t *testing.T,
	name string,
) *daemonIncarnation {
	t.Helper()
	logDir := filepath.Join(e.workDir, "logs-"+name)
	require.NoError(t, os.MkdirAll(logDir, 0755))

	args := []string{
		"fuse",
		"--bootstrap", e.bootstrap,
		"--blob-dir", e.blobDir,
		"--mountpoint", e.mntDir,
		"--control-socket", e.ctlSock,
		"--supervisor-socket", e.supervisorSock,
		"--log-dir", logDir,
		"--recover",
	}

	d := &daemonIncarnation{
		name:    name,
		exited:  make(chan struct{}),
		console: filepath.Join(e.workDir, name+".console.log"),
		logDir:  logDir,
	}
	logFile, err := os.Create(d.console)
	require.NoError(t, err)
	defer func() { _ = logFile.Close() }()
	cmd := exec.Command(e.nydusBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if e.reserveRecovery != nil {
		require.NoError(t, e.reserveRecovery())
	}
	require.NoError(t, cmd.Start())
	if e.authorizeRecovery != nil {
		if err := e.authorizeRecovery(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			require.NoError(t, err)
		}
	}
	d.cmd = cmd
	go func() {
		_ = cmd.Wait()
		if e.releaseRecovery != nil {
			e.releaseRecovery(cmd.Process.Pid)
		}
		close(d.exited)
	}()

	t.Cleanup(func() {
		if d.alive() {
			_ = d.cmd.Process.Kill()
			<-d.exited
		}
		if t.Failed() {
			t.Logf("--- %s console log ---\n%s", d.name, d.logCorpus())
		}
	})
	return d
}

// recoveryInheritedFD is the child-side descriptor of the socketpair that
// drives the held-handle helper process.
const recoveryInheritedFD = 3

// newRecoveryChannel creates that socketpair, returning the test-side
// connection and the child-side file to inherit.
func newRecoveryChannel(t *testing.T) (*net.UnixConn, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)

	holderFile := os.NewFile(uintptr(fds[0]), "recovery-holder")
	childFile := os.NewFile(uintptr(fds[1]), "recovery-child")
	cleanup := func() {
		if holderFile != nil {
			_ = holderFile.Close()
		}
		if childFile != nil {
			_ = childFile.Close()
		}
	}
	conn, err := net.FileConn(holderFile)
	if err != nil {
		cleanup()
		require.NoError(t, err)
	}
	if err := holderFile.Close(); err != nil {
		_ = conn.Close()
		cleanup()
		require.NoError(t, err)
	}
	holderFile = nil
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		cleanup()
	}
	require.True(t, ok, "expected UnixConn from recovery socketpair")
	return unixConn, childFile
}

func setRecoveryDeadline(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(recoveryProtocolTimeout)))
}

func TestValidateInflightJournalHeader(t *testing.T) {
	valid := make([]byte, inflightJournalHeaderSize)
	copy(valid[:8], []byte{'F', 'U', 'S', 'R', 'I', 'F', 'L', 0})
	binary.NativeEndian.PutUint32(
		valid[inflightJournalVersionOffset:inflightJournalCapacityOffset],
		2,
	)

	require.NoError(t, validateInflightJournalHeader(valid))

	badMagic := append([]byte(nil), valid...)
	badMagic[0] = 'X'
	require.ErrorContains(t, validateInflightJournalHeader(badMagic), "magic")

	badVersion := append([]byte(nil), valid...)
	binary.NativeEndian.PutUint32(
		badVersion[inflightJournalVersionOffset:inflightJournalCapacityOffset],
		1,
	)
	require.ErrorContains(t, validateInflightJournalHeader(badVersion), "version")
}

func validateInflightJournalHeader(header []byte) error {
	if len(header) < inflightJournalHeaderSize {
		return fmt.Errorf(
			"inflight journal header is %d bytes, expected at least %d",
			len(header),
			inflightJournalHeaderSize,
		)
	}
	if string(header[:inflightJournalVersionOffset]) != inflightJournalMagic {
		return fmt.Errorf("unexpected inflight journal magic %q", header[:8])
	}
	version := binary.NativeEndian.Uint32(
		header[inflightJournalVersionOffset:inflightJournalCapacityOffset],
	)
	if version != inflightJournalVersion {
		return fmt.Errorf(
			"unexpected inflight journal version %d, expected %d",
			version,
			inflightJournalVersion,
		)
	}
	return nil
}

func mapInflightJournal(t *testing.T, fd int, protection int) []byte {
	t.Helper()
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &stat))
	require.GreaterOrEqual(t, stat.Size, int64(inflightJournalHeaderSize+inflightJournalSlotSize))
	mapping, err := unix.Mmap(
		fd,
		0,
		int(stat.Size),
		protection,
		unix.MAP_SHARED,
	)
	require.NoError(t, err)
	require.NoError(t, validateInflightJournalHeader(mapping))
	capacity := int(binary.NativeEndian.Uint32(
		mapping[inflightJournalCapacityOffset:inflightJournalHeaderSize],
	))
	require.LessOrEqual(
		t,
		inflightJournalHeaderSize+capacity*inflightJournalSlotSize,
		len(mapping),
	)
	return mapping
}

func inflightSlotOffset(index int) int {
	return inflightJournalHeaderSize + index*inflightJournalSlotSize
}

func countInflightSlots(mapping []byte, state uint32) int {
	capacity := int(binary.NativeEndian.Uint32(
		mapping[inflightJournalCapacityOffset:inflightJournalHeaderSize],
	))
	count := 0
	for index := 0; index < capacity; index++ {
		offset := inflightSlotOffset(index)
		if binary.NativeEndian.Uint32(mapping[offset:offset+4]) == state {
			count++
		}
	}
	return count
}

func killWithJournaledStressRequest(
	t *testing.T,
	daemon *daemonIncarnation,
	journalFD int,
	beforeKill func(),
) int {
	t.Helper()
	mapping := mapInflightJournal(t, journalFD, unix.PROT_READ)
	defer func() { require.NoError(t, unix.Munmap(mapping)) }()

	for attempt := 0; attempt < 100; attempt++ {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if countInflightSlots(mapping, inflightSlotPublished) == 0 {
				runtime.Gosched()
				continue
			}

			require.NoError(t, daemon.cmd.Process.Signal(unix.SIGSTOP))
			time.Sleep(2 * time.Millisecond)
			published := countInflightSlots(mapping, inflightSlotPublished)
			if published == 0 {
				require.NoError(t, daemon.cmd.Process.Signal(unix.SIGCONT))
				continue
			}

			beforeKill()
			require.NoError(t, daemon.cmd.Process.Kill())
			require.True(t, daemon.waitExit(30*time.Second),
				"the daemon did not exit after a stress request was trapped")
			require.False(t, daemon.cmd.ProcessState.Success(),
				"the daemon unexpectedly exited cleanly after SIGKILL")
			published = countInflightSlots(mapping, inflightSlotPublished)
			require.Greater(t, published, 0,
				"the trapped stress request disappeared from the journal after the crash")
			return published
		}
	}
	t.Fatal("continuous stress did not publish a FUSE request before the deadline")
	return 0
}

func requestControlInfo(path string) (ctlResponse, error) {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return ctlResponse{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return ctlResponse{}, err
	}

	payload, err := json.Marshal(map[string]any{"type": "info"})
	if err != nil {
		return ctlResponse{}, err
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)))
	frameBytes := append(header[:], payload...)
	if _, err := io.Copy(conn, bytes.NewReader(frameBytes)); err != nil {
		return ctlResponse{}, err
	}

	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return ctlResponse{}, err
	}
	length := binary.LittleEndian.Uint32(header[:])
	if length == 0 || length > 4<<20 {
		return ctlResponse{}, fmt.Errorf("invalid control frame length %d", length)
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(conn, response); err != nil {
		return ctlResponse{}, err
	}
	var responseFrame ctlResponse
	if err := json.Unmarshal(response, &responseFrame); err != nil {
		return ctlResponse{}, err
	}
	if responseFrame.Type != "info" || responseFrame.Info == nil {
		return ctlResponse{}, fmt.Errorf("unexpected control response %q", responseFrame.Type)
	}
	return responseFrame, nil
}

func controlOwnerPID(path string) (uint32, error) {
	response, err := requestControlInfo(path)
	if err != nil {
		return 0, err
	}
	return response.Info.Pid, nil
}

type fakeHotUpgradeSuccessor struct {
	cmd    *exec.Cmd
	logs   bytes.Buffer
	waited bool
}

func (e *fuseSessionHarness) startFakeHotUpgradeSuccessor(
	t *testing.T,
) *fakeHotUpgradeSuccessor {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFusePreReadyHelper$")
	cmd.Env = append(os.Environ(),
		"NYDUS_FUSE_PRE_READY_SUCCESSOR_HELPER=1",
		"NYDUS_FUSE_CONTROL_SOCKET="+e.ctlSock,
		"NYDUS_FUSE_MOUNTPOINT="+e.mntDir,
		"NYDUS_FUSE_BOOTSTRAP="+e.bootstrap,
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	successor := &fakeHotUpgradeSuccessor{cmd: cmd}
	cmd.Stderr = &successor.logs
	require.NoError(t, cmd.Start())
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && strings.TrimSpace(line) != "TRANSFERRED" {
			readErr = fmt.Errorf("unexpected helper readiness %q", strings.TrimSpace(line))
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		require.NoError(t, err, successor.logs.String())
	case <-time.After(10 * time.Second):
		require.FailNow(t, "pre-READY successor did not receive the Session Transfer",
			successor.logs.String())
	}
	t.Cleanup(successor.cleanup)
	return successor
}

func (s *fakeHotUpgradeSuccessor) abandonBeforeReady(t *testing.T, delay time.Duration) {
	t.Helper()
	time.Sleep(delay)
	require.NoError(t, s.cmd.Process.Kill())
	require.Error(t, s.cmd.Wait())
	s.waited = true
}

func (s *fakeHotUpgradeSuccessor) cleanup() {
	if s.waited {
		return
	}
	_ = s.cmd.Process.Kill()
	_ = s.cmd.Wait()
	s.waited = true
}

type recoveryHandleReport struct {
	Ready      bool     `json:"ready,omitempty"`
	PreNames   int      `json:"pre_names,omitempty"`
	FileSize   int      `json:"file_size,omitempty"`
	FileDigest string   `json:"file_digest,omitempty"`
	DirNames   []string `json:"dir_names,omitempty"`
}

type recoveryHandleKeeper struct {
	cmd    *exec.Cmd
	conn   *net.UnixConn
	logs   bytes.Buffer
	waited bool
}

func startRecoveryHandleKeeper(t *testing.T, env *fuseSessionHarness) *recoveryHandleKeeper {
	t.Helper()
	conn, childFile := newRecoveryChannel(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestFuseHeldHandleHelper$")
	cmd.Env = append(os.Environ(),
		"NYDUS_FUSE_HANDLE_HELPER=1",
		"NYDUS_FUSE_HANDLE_FILE="+filepath.Join(env.mntDir, recoveryHeldFileRel),
		"NYDUS_FUSE_HANDLE_DIR="+filepath.Join(env.mntDir, heldDirRel),
	)
	cmd.ExtraFiles = []*os.File{childFile}
	keeper := &recoveryHandleKeeper{cmd: cmd, conn: conn}
	cmd.Stdout = &keeper.logs
	cmd.Stderr = &keeper.logs
	require.NoError(t, cmd.Start())
	require.NoError(t, childFile.Close())

	setRecoveryDeadline(t, conn)
	var ready recoveryHandleReport
	require.NoError(t, json.NewDecoder(conn).Decode(&ready), keeper.logs.String())
	require.True(t, ready.Ready, keeper.logs.String())
	require.Greater(t, ready.PreNames, 0)
	require.Less(t, ready.PreNames, heldDirEntries)
	require.NoError(t, conn.SetDeadline(time.Time{}))

	t.Cleanup(func() {
		if keeper.waited {
			return
		}
		_ = keeper.conn.Close()
		_ = keeper.cmd.Process.Kill()
		_ = keeper.cmd.Wait()
		keeper.waited = true
		if t.Failed() {
			t.Logf("--- held-handle helper log ---\n%s", keeper.logs.String())
		}
	})
	return keeper
}

func (k *recoveryHandleKeeper) verify(t *testing.T, expectedFile []byte) {
	t.Helper()
	setRecoveryDeadline(t, k.conn)
	require.NoError(t, json.NewEncoder(k.conn).Encode(map[string]string{"type": "verify"}))
	var report recoveryHandleReport
	require.NoError(t, json.NewDecoder(k.conn).Decode(&report), k.logs.String())
	require.Equal(t, len(expectedFile), report.FileSize)
	expectedDigest := sha256.Sum256(expectedFile)
	require.Equal(t, fmt.Sprintf("%x", expectedDigest), report.FileDigest)
	require.Len(t, report.DirNames, heldDirEntries)
	sort.Strings(report.DirNames)
	for i, name := range report.DirNames {
		require.Equal(t, fmt.Sprintf("entry_%04d", i), name)
	}

	require.NoError(t, k.conn.Close())
	require.NoError(t, k.cmd.Wait(), k.logs.String())
	k.waited = true
}

func (env *fuseSessionHarness) requireRecoveredFilesystem(
	t *testing.T,
	want []byte,
	wantDev uint64,
) {
	t.Helper()
	env.requireMountIdentity(t, wantDev, "recovery replaced the FUSE mount")
	got, err := readFileRaw(filepath.Join(env.mntDir, stressFileRel))
	require.NoError(t, err)
	require.Equal(t, want, got)
	var stat unix.Stat_t
	require.NoError(t, unix.Stat(filepath.Join(env.mntDir, stressFileRel), &stat))
	require.Equal(t, int64(len(want)), stat.Size)
	entries, err := countDirEntriesRaw(filepath.Join(env.mntDir, heldDirRel))
	require.NoError(t, err)
	require.Equal(t, heldDirEntries, entries)
}

// -----------------------------------------------------------------------------
// Recovery Holder protocol and test double
// -----------------------------------------------------------------------------

const recoveryProtocolTimeout = 10 * time.Second

// ctlInstanceInfo mirrors the handoff instance information on the wire.
type ctlInstanceInfo struct {
	Pid         uint32 `json:"pid"`
	Version     string `json:"version"`
	Mountpoint  string `json:"mountpoint"`
	ImageDigest string `json:"image_digest"`
}

// ctlResponse is the union of the control and supervisor frames we care about.
type ctlResponse struct {
	Type        string           `json:"type"`
	Message     string           `json:"message,omitempty"`
	State       json.RawMessage  `json:"state,omitempty"`
	Info        *ctlInstanceInfo `json:"info,omitempty"`
	Mountpoint  string           `json:"mountpoint,omitempty"`
	ImageDigest string           `json:"image_digest,omitempty"`
	SessionID   string           `json:"session_id,omitempty"`
}

type ctlFuseSessionState struct {
	ProtoMajor          uint32 `json:"proto_major"`
	ProtoMinor          uint32 `json:"proto_minor"`
	NegotiatedInitFlags uint64 `json:"negotiated_init_flags"`
	KernelInitFlags     uint64 `json:"kernel_init_flags"`
}

type ctlRecoveryState struct {
	SessionID        string              `json:"session_id"`
	Mountpoint       string              `json:"mountpoint"`
	ImageDigest      string              `json:"image_digest"`
	FuseSessionState ctlFuseSessionState `json:"fuse_session_state"`
}

type recoveryBundle struct {
	Metadata []byte
	FDs      [2]int
}

func (e *recoveryBundle) close() {
	for i, fd := range e.FDs {
		if fd >= 0 {
			_ = unix.Close(fd)
			e.FDs[i] = -1
		}
	}
}

// fakeRecoveryHolder is the external Recovery Holder side of the continuity
// contract. It owns and listens on the Holder socket, retains the Session
// Transfer a Failover-Protected Session sends at startup, and sends retained
// copies to a Supervisor-authorized recovery child. Launch context determines
// direction; every Daemon Incarnation connects as a client and sends no
// command.
// Tests that need independent descriptor copies duplicate the retained bundle
// directly from this stored state.
type fakeRecoveryHolder struct {
	t        *testing.T
	harness  *fuseSessionHarness
	listener *net.UnixListener
	workers  sync.WaitGroup

	mu     sync.Mutex
	bundle *recoveryBundle
	faults []string

	recoveryLaunchReady chan struct{}
	expectedRecoveryPID int
	activeRecoveryPID   int
}

func newFakeRecoveryHolder(
	t *testing.T,
	harness *fuseSessionHarness,
) *fakeRecoveryHolder {
	t.Helper()
	holder := &fakeRecoveryHolder{t: t, harness: harness}
	harness.reserveRecovery = holder.reserveRecovery
	harness.authorizeRecovery = holder.authorizeRecovery
	harness.releaseRecovery = holder.releaseRecoveryProcess
	t.Cleanup(holder.cleanup)
	if harness.supervisorSock == "" {
		return holder
	}

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: harness.supervisorSock, Net: "unix"},
	)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(harness.supervisorSock, 0600))
	holder.listener = listener
	holder.workers.Add(1)
	go func() {
		defer holder.workers.Done()
		holder.serve()
	}()
	return holder
}

func (h *fakeRecoveryHolder) reserveRecovery() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.recoveryLaunchReady != nil || h.expectedRecoveryPID != 0 {
		return fmt.Errorf("a recovery child launch is already pending")
	}
	if h.activeRecoveryPID != 0 {
		return fmt.Errorf("another recovery is already active")
	}
	h.recoveryLaunchReady = make(chan struct{})
	return nil
}

func (h *fakeRecoveryHolder) authorizeRecovery(pid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.recoveryLaunchReady == nil {
		return fmt.Errorf("no recovery child launch is pending")
	}
	if pid <= 0 {
		close(h.recoveryLaunchReady)
		h.recoveryLaunchReady = nil
		return fmt.Errorf("invalid recovery child pid %d", pid)
	}
	h.expectedRecoveryPID = pid
	close(h.recoveryLaunchReady)
	h.recoveryLaunchReady = nil
	return nil
}

func (h *fakeRecoveryHolder) releaseRecoveryProcess(pid int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if pid == 0 {
		if h.recoveryLaunchReady != nil {
			close(h.recoveryLaunchReady)
			h.recoveryLaunchReady = nil
		}
		h.expectedRecoveryPID = 0
		return
	}
	if h.expectedRecoveryPID == pid {
		h.expectedRecoveryPID = 0
	}
	if h.activeRecoveryPID == pid {
		h.activeRecoveryPID = 0
	}
}

func supervisorPeerCredentials(conn *net.UnixConn) (int, uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil {
		return 0, 0, err
	}
	if credentialErr != nil {
		return 0, 0, credentialErr
	}
	if credentials == nil || credentials.Pid <= 0 {
		return 0, 0, fmt.Errorf("supervisor peer has invalid credentials")
	}
	return int(credentials.Pid), credentials.Uid, nil
}

func (h *fakeRecoveryHolder) serve() {
	for {
		conn, err := h.listener.AcceptUnix()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				h.recordFault(fmt.Sprintf("supervisor accept failed: %v", err))
			}
			return
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			defer func() { _ = conn.Close() }()
			if err := h.handle(conn); err != nil {
				h.recordFault(fmt.Sprintf("Holder transaction failed: %v", err))
			}
		}()
	}
}

// handle serves exactly one launch-context transaction. A recovery child gets
// retained descriptor copies; a fresh child sends a replacement transfer.
func (h *fakeRecoveryHolder) handle(conn *net.UnixConn) error {
	if err := conn.SetDeadline(time.Now().Add(recoveryProtocolTimeout)); err != nil {
		return err
	}
	peerPID, peerUID, err := supervisorPeerCredentials(conn)
	if err != nil {
		return err
	}
	if peerUID != uint32(os.Geteuid()) {
		return fmt.Errorf(
			"supervisor peer uid %d differs from holder uid %d",
			peerUID,
			os.Geteuid(),
		)
	}
	h.mu.Lock()
	if h.expectedRecoveryPID == 0 && h.recoveryLaunchReady != nil {
		ready := h.recoveryLaunchReady
		h.mu.Unlock()
		select {
		case <-ready:
		case <-time.After(recoveryProtocolTimeout):
			return fmt.Errorf("timed out authorizing recovery child")
		}
		h.mu.Lock()
	}
	if h.expectedRecoveryPID != 0 {
		if h.activeRecoveryPID != 0 {
			h.mu.Unlock()
			return fmt.Errorf("another recovery is already active")
		}
		if h.expectedRecoveryPID != peerPID {
			h.mu.Unlock()
			return fmt.Errorf("peer is not the expected recovery child")
		}
		h.activeRecoveryPID = peerPID
		h.expectedRecoveryPID = 0
		if h.bundle == nil {
			h.activeRecoveryPID = 0
			h.mu.Unlock()
			return fmt.Errorf("no Session Transfer is retained")
		}
		metadata := append([]byte(nil), h.bundle.Metadata...)
		fds := make([]int, 0, len(h.bundle.FDs))
		for _, fd := range h.bundle.FDs {
			duplicate, dupErr := unix.Dup(fd)
			if dupErr != nil {
				closeFDs(fds)
				h.mu.Unlock()
				return dupErr
			}
			fds = append(fds, duplicate)
		}
		h.mu.Unlock()
		defer closeFDs(fds)
		if err := writeRawFrame(conn, metadata); err != nil {
			return err
		}
		return sendRecoveryDescriptors(conn, fds)
	}
	h.mu.Unlock()

	metadata, err := readRawFrame(conn)
	if err != nil {
		return err
	}
	fds, err := recvFDsExact(conn, 2)
	if err != nil {
		return err
	}
	stored := &recoveryBundle{Metadata: metadata, FDs: [2]int{fds[0], fds[1]}}
	h.mu.Lock()
	if h.bundle != nil {
		h.bundle.close()
	}
	h.bundle = stored
	h.mu.Unlock()
	return writeControlFrame(conn, map[string]any{"type": "retained"})
}

func (h *fakeRecoveryHolder) recordFault(message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.faults = append(h.faults, message)
}

// storedMetadata returns a copy of the retained opaque metadata, if any.
func (h *fakeRecoveryHolder) storedMetadata() ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.bundle == nil {
		return nil, false
	}
	return append([]byte(nil), h.bundle.Metadata...), true
}

// storedState decodes a copied metadata buffer for test assertions only.
func (h *fakeRecoveryHolder) storedState() (ctlRecoveryState, bool) {
	metadata, ok := h.storedMetadata()
	if !ok {
		return ctlRecoveryState{}, false
	}
	var state ctlRecoveryState
	if err := json.Unmarshal(metadata, &state); err != nil {
		h.recordFault(fmt.Sprintf("decode stored recovery metadata: %v", err))
		return ctlRecoveryState{}, false
	}
	return state, true
}

// requireStoredBundle asserts that a Failover-Protected Session stored its
// transfer before the mount became usable, and returns the retained state.
func (h *fakeRecoveryHolder) requireStoredBundle() ctlRecoveryState {
	h.t.Helper()
	var state ctlRecoveryState
	require.Eventually(h.t, func() bool {
		stored, ok := h.storedState()
		state = stored
		return ok
	}, 10*time.Second, 100*time.Millisecond,
		"the Failover-Protected Session never stored its Session Transfer in the Holder")
	require.NotEmpty(h.t, state.SessionID)
	require.NotEmpty(h.t, state.Mountpoint)
	require.NotEmpty(h.t, state.ImageDigest)
	return state
}

func (h *fakeRecoveryHolder) requireStoredBundleCopy() *recoveryBundle {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotNil(h.t, h.bundle)
	bundleCopy, err := duplicateRecoveryBundle(h.bundle)
	require.NoError(h.t, err)
	h.t.Cleanup(bundleCopy.close)
	return bundleCopy
}

func duplicateRecoveryBundle(bundle *recoveryBundle) (*recoveryBundle, error) {
	bundleCopy := &recoveryBundle{
		Metadata: append([]byte(nil), bundle.Metadata...),
		FDs:      [2]int{-1, -1},
	}
	for index, fd := range bundle.FDs {
		duplicate, err := unix.Dup(fd)
		if err != nil {
			bundleCopy.close()
			return nil, err
		}
		bundleCopy.FDs[index] = duplicate
	}
	return bundleCopy, nil
}

func (h *fakeRecoveryHolder) release(bundle *recoveryBundle) {
	bundle.close()
}

func (h *fakeRecoveryHolder) closeRetainedTransfer() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.bundle != nil {
		h.bundle.close()
		h.bundle = nil
	}
}

func (h *fakeRecoveryHolder) cleanup() {
	if h.listener != nil {
		_ = h.listener.Close()
	}
	h.workers.Wait()
	h.closeRetainedTransfer()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, fault := range h.faults {
		h.t.Errorf("%s", fault)
	}
}

func sendRecoveryDescriptors(conn *net.UnixConn, fds []int) error {
	oob := unix.UnixRights(fds...)
	n, oobn, err := conn.WriteMsgUnix([]byte{'F'}, oob, nil)
	if err != nil {
		return err
	}
	if n != 1 || oobn != len(oob) {
		return fmt.Errorf("short recovery descriptor write: payload=%d oob=%d want=1/%d", n, oobn, len(oob))
	}
	return nil
}

func writeRawFrame(conn net.Conn, payload []byte) error {
	if len(payload) == 0 || len(payload) > 4<<20 {
		return fmt.Errorf("invalid control frame length %d", len(payload))
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	frameBytes := append(hdr[:], payload...)
	written, err := io.Copy(conn, bytes.NewReader(frameBytes))
	if err != nil {
		return err
	}
	if written != int64(len(frameBytes)) {
		return io.ErrShortWrite
	}
	return nil
}

func readRawFrame(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > 4<<20 {
		return nil, fmt.Errorf("invalid control frame length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeControlFrame(conn net.Conn, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeRawFrame(conn, payload)
}

func readControlFrame(conn net.Conn) (ctlResponse, error) {
	payload, err := readRawFrame(conn)
	if err != nil {
		return ctlResponse{}, err
	}
	var response ctlResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return ctlResponse{}, fmt.Errorf("decode control frame: %w", err)
	}
	return response, nil
}

func recvFDsExact(conn *net.UnixConn, expected int) (fds []int, err error) {
	if expected <= 0 {
		return nil, fmt.Errorf("invalid expected fd count %d", expected)
	}
	defer func() {
		if err != nil {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
	}()

	if err = conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace((expected+1)*4))
	var n, oobn, flags int
	var recvErr error
	if err = raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, _, recvErr = unix.Recvmsg(
				int(fd),
				payload,
				oob,
				unix.MSG_CMSG_CLOEXEC,
			)
			if recvErr == unix.EINTR {
				continue
			}
			return recvErr != unix.EAGAIN
		}
	}); err != nil {
		return nil, err
	}
	if recvErr != nil {
		return nil, recvErr
	}
	if n != 1 || payload[0] != 'F' || flags&unix.MSG_CTRUNC != 0 {
		return nil, fmt.Errorf("invalid descriptor transfer payload")
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			return fds, fmt.Errorf("unexpected control message")
		}
		rights, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil {
			return fds, parseErr
		}
		fds = append(fds, rights...)
	}
	if len(fds) != expected {
		return fds, fmt.Errorf("received %d descriptors, expected %d", len(fds), expected)
	}
	for _, fd := range fds {
		fdFlags, fcntlErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if fcntlErr != nil {
			return fds, fcntlErr
		}
		if fdFlags&unix.FD_CLOEXEC == 0 {
			return fds, fmt.Errorf("received descriptor %d without FD_CLOEXEC", fd)
		}
	}
	return fds, nil
}

// writeCtlFrame sends one length-prefixed JSON frame.
func writeCtlFrame(t *testing.T, conn net.Conn, v any) {
	t.Helper()
	require.NoError(t, writeControlFrame(conn, v))
}

// readCtlFrame reads one length-prefixed JSON frame.
func readCtlFrame(t *testing.T, conn net.Conn) ctlResponse {
	t.Helper()
	response, err := readControlFrame(conn)
	require.NoError(t, err)
	return response
}

// -----------------------------------------------------------------------------
// FUSE continuity scenarios
// -----------------------------------------------------------------------------

func TestFuseHotUpgrade(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("FUSE hot-upgrade E2E requires root")
	}

	env, _ := setupFailoverHarness(t)
	holder := newFakeRecoveryHolder(t, env)
	heldSource, err := os.ReadFile(filepath.Join(env.sourceDir, heldFileRel))
	require.NoError(t, err)
	stressSource, err := os.ReadFile(filepath.Join(env.sourceDir, stressFileRel))
	require.NoError(t, err)

	old := env.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the first daemon failed to mount")
	stored := holder.requireStoredBundle()
	sessionID := stored.SessionID
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"the first daemon did not publish the retained Session Identity")
	require.FileExists(t, env.ctlSock+".lock",
		"startup did not create its ownership lock beside the control socket")
	devOld := env.mountIdentity(t)
	roDiffTree(t, env.sourceDir, env.mntDir, true)

	// A held file fd, a half-read directory handle, and a
	// continuous open+read+readdir stress loop all ride across the handoff.
	held, err := os.Open(filepath.Join(env.mntDir, heldFileRel))
	require.NoError(t, err)
	defer func() { _ = held.Close() }()
	firstHalf := make([]byte, heldFileSize/2)
	_, err = io.ReadFull(held, firstHalf)
	require.NoError(t, err)
	require.True(t, bytes.Equal(heldSource[:heldFileSize/2], firstHalf),
		"pre-upgrade read through the held fd differs from the source")

	heldDir := openPartialDirReader(t, filepath.Join(env.mntDir, heldDirRel))
	require.False(t, heldDir.readBatch(t), "the held directory was exhausted in one small batch")
	preNames := len(heldDir.names)
	require.Greater(t, preNames, 0, "the first getdents batch returned no entries")
	require.Less(t, preNames, heldDirEntries, "the held directory must be only partially read")

	stress := startIOStress(env.mntDir, stressSource)

	successor := env.spawnDaemonIncarnation(t, "new", "--upgrade")
	env.requireServingSession(t, successor, sessionID, 30*time.Second, 200*time.Millisecond,
		"the successor did not publish the original Session Identity")
	require.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
		"hot upgrade replaced the Holder's retained Session Transfer")
	env.requireMountIdentity(t, devOld,
		"the mount must not move across an fd handoff (same st_dev)")
	require.True(t, successor.alive(), "the successor exited right after the takeover")
	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "fd handoff complete")
	}, 10*time.Second, 200*time.Millisecond, "the old daemon did not log handoff completion")
	// No drain phase: the successor serves every already-open fd on the same
	// connection, so the old daemon retires immediately even though `held`
	// and `heldDir` are still open.
	require.True(t, old.waitExit(30*time.Second),
		"the old daemon did not exit after the handoff despite having nothing left to serve")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero after the handoff: %v", old.cmd.ProcessState)

	// State carried across the handoff keeps working: the held file fd
	// reads byte-exactly and the half-read directory handle lists the rest.
	secondHalf, err := io.ReadAll(held)
	require.NoError(t, err)
	require.Len(t, secondHalf, heldFileSize/2)
	require.True(t, bytes.Equal(heldSource[heldFileSize/2:], secondHalf),
		"post-upgrade read through the held fd differs from the source")
	require.NoError(t, held.Close())

	heldDir.readRest(t)
	heldDir.close()
	require.Len(t, heldDir.names, heldDirEntries,
		"the directory handle did not list every entry after takeover")
	sort.Strings(heldDir.names)
	for i, name := range heldDir.names {
		require.Equal(t, fmt.Sprintf("entry_%04d", i), name, "unexpected directory entry")
	}

	// New opens are served by the successor and the whole tree still
	// matches the source; the control socket has been re-published.
	roDiffTree(t, env.sourceDir, env.mntDir, true)
	_, err = os.Stat(env.ctlSock)
	require.NoError(t, err, "the successor did not re-publish the control socket")

	// The stress loop saw zero errors and only a bounded handoff stall.
	ops, errs, maxStall := stress.stop()
	t.Logf("stress: %d iterations across hot upgrade, max stall %v", ops, maxStall)
	require.Greater(t, ops, int64(0), "the stress loop never completed an iteration")
	require.Empty(t, errs, "IO errors during hot upgrade: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall,
		"a stress iteration stalled for %v — the handoff pause is not bounded", maxStall)

	// Graceful shutdown of the adopted generation unmounts and exits 0. Keep
	// an fd open to force the EBUSY -> MNT_DETACH path.
	shutdownHeld, err := os.Open(filepath.Join(env.mntDir, heldFileRel))
	require.NoError(t, err)
	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the final daemon ignored SIGTERM")
	require.True(t, successor.cmd.ProcessState.Success(),
		"the final daemon exited non-zero on SIGTERM: %v", successor.cmd.ProcessState)
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
	// End the detached connection before closing the client handle; otherwise
	// its FUSE RELEASE has no serving daemon and can block indefinitely.
	holder.closeRetainedTransfer()
	_ = shutdownHeld.Close()
}

func TestFusePreReadyRollback(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("FUSE hot-upgrade E2E requires root")
	}

	env, stressSource := setupFailoverHarness(t)
	newFakeRecoveryHolder(t, env)

	old := env.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the daemon failed to mount")
	devOld := env.mountIdentity(t)
	stress := startIOStress(env.mntDir, stressSource)

	// Pose as a successor with matching session context and a real handoff request.
	fakeSuccessor := env.startFakeHotUpgradeSuccessor(t)

	// The old daemon is paused now; the kernel queues requests. Give the
	// stress loop time to pile a few up, then "crash" before reporting ready:
	// close our fd copy and the control connection (EOF).
	fakeSuccessor.abandonBeforeReady(t, 2*time.Second)

	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "resuming service")
	}, 15*time.Second, 200*time.Millisecond,
		"the old daemon did not resume after the successor died")
	require.True(t, old.alive(), "the old daemon must survive an aborted handoff")
	env.requireMountIdentity(t, devOld, "the mount must be untouched")

	// The queued requests must have been served: keep stressing a little,
	// then assert zero errors across the pause + resume.
	time.Sleep(2 * time.Second)
	ops, errs, maxStall := stress.stop()
	t.Logf("stress: %d iterations across the aborted handoff, max stall %v", ops, maxStall)
	require.Greater(t, ops, int64(0), "the stress loop never completed an iteration")
	require.Empty(t, errs, "IO errors during the aborted handoff: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall,
		"a stress iteration stalled for %v — the fallback did not resume promptly", maxStall)
	roDiffTree(t, env.sourceDir, env.mntDir, true)

	// A real upgrade must still work after the aborted one.
	successor := env.spawnDaemonIncarnation(t, "new", "--upgrade")
	env.requireControlOwner(t, successor, 30*time.Second, 200*time.Millisecond,
		"upgrade after an aborted handoff did not publish control ownership")
	require.True(t, old.waitExit(30*time.Second), "the old daemon did not retire")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero: %v", old.cmd.ProcessState)
	roDiffTree(t, env.sourceDir, env.mntDir, true)

	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the successor ignored SIGTERM")
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
}

// -----------------------------------------------------------------------------
// Hot-upgrade and crash-failover helper processes
// -----------------------------------------------------------------------------

func TestFusePreReadyHelper(t *testing.T) {
	if os.Getenv("NYDUS_FUSE_PRE_READY_SUCCESSOR_HELPER") != "1" {
		t.Skip("helper process for TestFusePreReadyRollback")
	}

	mountpoint, err := filepath.EvalSymlinks(os.Getenv("NYDUS_FUSE_MOUNTPOINT"))
	require.NoError(t, err)
	imageBytes, err := os.ReadFile(os.Getenv("NYDUS_FUSE_BOOTSTRAP"))
	require.NoError(t, err)
	imageDigest := sha256.Sum256(imageBytes)
	conn, err := net.Dial("unix", os.Getenv("NYDUS_FUSE_CONTROL_SOCKET"))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	writeCtlFrame(t, conn, map[string]any{
		"type": "handoff_begin",
		"peer": ctlInstanceInfo{
			Pid:         uint32(os.Getpid()),
			Version:     "e2e-pre-ready-successor",
			Mountpoint:  mountpoint,
			ImageDigest: fmt.Sprintf("%x", imageDigest),
		},
	})
	response := readCtlFrame(t, conn)
	require.Equal(t, "handoff_transfer", response.Type,
		"pre-READY successor expected a protected Session Transfer, got %q: %s",
		response.Type, response.Message)
	metadata, err := readRawFrame(conn)
	require.NoError(t, err)
	require.NotEmpty(t, metadata)
	fds, err := recvFDsExact(conn.(*net.UnixConn), 2)
	require.NoError(t, err)
	defer closeFDs(fds)

	_, err = fmt.Fprintln(os.Stdout, "TRANSFERRED")
	require.NoError(t, err)
	select {}
}

func TestFuseHeldHandleHelper(t *testing.T) {
	if os.Getenv("NYDUS_FUSE_HANDLE_HELPER") != "1" {
		t.Skip("helper process for TestFuseFailoverMatrix")
	}

	protocol := os.NewFile(uintptr(recoveryInheritedFD), "held-handle-protocol")
	require.NotNil(t, protocol)
	defer func() { _ = protocol.Close() }()

	fileFD, err := unix.Open(
		os.Getenv("NYDUS_FUSE_HANDLE_FILE"),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	require.NoError(t, err)
	defer func() { _ = unix.Close(fileFD) }()
	heldDir := openPartialDirReader(t, os.Getenv("NYDUS_FUSE_HANDLE_DIR"))
	require.False(t, heldDir.readBatch(t), "the held directory was exhausted before recovery")
	require.NoError(t, json.NewEncoder(protocol).Encode(recoveryHandleReport{
		Ready:    true,
		PreNames: len(heldDir.names),
	}))

	decoder := json.NewDecoder(protocol)
	encoder := json.NewEncoder(protocol)
	for {
		var command map[string]string
		require.NoError(t, decoder.Decode(&command))
		switch command["type"] {
		case "verify":
			fileBytes, err := readAtRaw(fileFD, stressFileSize)
			require.NoError(t, err)
			heldDir.readRest(t)
			heldDir.close()
			fileDigest := sha256.Sum256(fileBytes)
			require.NoError(t, encoder.Encode(recoveryHandleReport{
				FileSize:   len(fileBytes),
				FileDigest: fmt.Sprintf("%x", fileDigest),
				DirNames:   heldDir.names,
			}))
			return
		default:
			t.Fatalf("unexpected held-handle command %q", command["type"])
		}
	}
}

func TestFuseFailoverMatrix(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("FUSE failover acceptance test requires root")
	}

	env, stressSource := setupFailoverHarness(t)
	holder := newFakeRecoveryHolder(t, env)
	initial := env.spawnDaemonIncarnation(t, "matrix-initial")
	env.requireMounted(t, "the Failover-Protected Session failed to mount")
	env.requireControlOwner(t, initial, 10*time.Second, 100*time.Millisecond,
		"the Failover-Protected Session did not publish control ownership")

	heldHandles := startRecoveryHandleKeeper(t, env)
	stored := holder.requireStoredBundle()
	held := holder.requireStoredBundleCopy()
	sessionID := stored.SessionID
	var heldState ctlRecoveryState
	require.NoError(t, json.Unmarshal(held.Metadata, &heldState))
	require.Equal(t, sessionID, heldState.SessionID)
	mountDev := env.mountIdentity(t)
	stress := startFailoverIOStress(env.mntDir, stressSource)

	upgraded := env.spawnDaemonIncarnation(t, "matrix-upgraded", "--upgrade")
	env.requireServingSession(t, upgraded, sessionID, 30*time.Second, 200*time.Millisecond,
		"the hot-upgrade successor did not publish the original Session Identity")
	require.True(t, initial.waitExit(30*time.Second),
		"the initial daemon did not retire after hot upgrade")
	require.True(t, initial.cmd.ProcessState.Success(),
		"the initial daemon exited non-zero after hot upgrade")
	require.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
		"hot upgrade replaced the stored Session Transfer")
	env.requireRecoveredFilesystem(t, stressSource, mountDev)

	var crashGenerations []int64
	firstJournaled := killWithJournaledStressRequest(
		t,
		upgraded,
		held.FDs[1],
		func() { crashGenerations = append(crashGenerations, stress.markCrash()) },
	)
	env.requireControlUnavailable(t,
		"the upgraded daemon's control endpoint still answers after its crash")
	t.Logf("first crash retained %d published journal entries", firstJournaled)

	firstRecovery := env.spawnRecoveryDaemon(t, "matrix-recovery-1")
	env.requireServingSession(t, firstRecovery, sessionID, 30*time.Second, 100*time.Millisecond,
		"the first recovery did not publish the retained Session Identity")
	require.True(t, firstRecovery.alive(),
		"the first recovery exited after publishing its Session Identity")
	env.requireRecoveredFilesystem(t, stressSource, mountDev)

	secondJournaled := killWithJournaledStressRequest(
		t,
		firstRecovery,
		held.FDs[1],
		func() { crashGenerations = append(crashGenerations, stress.markCrash()) },
	)
	env.requireControlUnavailable(t,
		"the first recovery's control endpoint still answers after its crash")
	t.Logf("second crash retained %d published journal entries", secondJournaled)

	secondRecovery := env.spawnRecoveryDaemon(t, "matrix-recovery-2")
	env.requireServingSession(t, secondRecovery, sessionID, 30*time.Second, 100*time.Millisecond,
		"the second recovery did not serve the original Session Identity")
	env.requireRecoveredFilesystem(t, stressSource, mountDev)
	heldHandles.verify(t, stressSource)
	roDiffTree(t, env.sourceDir, env.mntDir, true)

	ops, errs, maxStall := stress.stop()
	eioByCrash := stress.failoverEIOs()
	t.Logf("failover matrix stress: %d iterations, EIOs by crash %v, max stall %v",
		ops, eioByCrash, maxStall)
	require.Greater(t, ops, int64(0))
	require.Empty(t, errs, "unexpected IO errors across the failover matrix: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall)
	require.Len(t, crashGenerations, 2)
	// At most one in-flight stress operation can span a given crash, whether
	// the kernel resends it, journal recovery errors it out (EIO), or its
	// worker clone queue died with the daemon (ECONNABORTED).
	for _, crash := range crashGenerations {
		require.LessOrEqual(t, eioByCrash[crash], int64(1),
			"at most one stress operation may observe an error spanning crash %d", crash)
	}

	holder.release(held)
	require.True(t, secondRecovery.alive(),
		"dropping holder descriptor copies tore down the recovered daemon")
	require.True(t, isMountpoint(env.mntDir),
		"dropping holder descriptor copies unmounted the FUSE session")

	shutdownBundle := holder.requireStoredBundleCopy()
	require.NoError(t, secondRecovery.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, secondRecovery.waitExit(30*time.Second),
		"the second recovery ignored explicit shutdown")
	require.True(t, secondRecovery.cmd.ProcessState.Success(),
		"the second recovery exited non-zero on explicit shutdown")
	env.requireUnmounted(t,
		"explicit shutdown did not unmount while the fake holder retained descriptor copies")
	holder.release(shutdownBundle)
}
