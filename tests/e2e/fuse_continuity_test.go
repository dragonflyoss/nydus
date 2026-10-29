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
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
)

const (
	heldFileRel        = "upgrade/held_8m.bin"
	heldFileSize       = 8 << 20
	heldFileXattrName  = "user.continuity"
	heldFileXattrValue = "held-across-handoff"

	stressFileRel       = "upgrade/stress_64k.bin"
	stressFileSize      = 64 << 10
	recoveryHeldFileRel = "upgrade/recovery-held-64k.bin"

	heldDirRel     = "upgrade/dirmany"
	heldDirEntries = 1024

	maxUpgradeStall         = 20 * time.Second
	recoveryProtocolTimeout = 10 * time.Second
	recoveryInheritedFD     = 3
	controlUpgradePath      = "/fuse/handoff"
	controlUpgradeProtocol  = "nydus-fuse-control/1"

	inflightJournalMagic                 = "FUSRIFL\x00"
	inflightJournalVersionOffset         = 8
	inflightJournalVersion        uint32 = 1
	inflightJournalCapacityOffset        = 12
	inflightJournalHeaderSize            = 16
	inflightJournalSlotSize              = 16
	inflightSlotTagMask           uint64 = 3
	inflightSlotTagInflight       uint64 = 2

	maxTransferFDs = 253
)

type fuseSessionHarness struct {
	nydusBin       string
	workDir        string
	sourceDir      string
	blobDir        string
	mntDir         string
	bootstrap      string
	ctlSock        string
	supervisorSock string

	holder *fakeRecoveryHolder
}

type daemonIncarnation struct {
	name    string
	cmd     *exec.Cmd
	exited  chan struct{}
	waitErr error
	console string
	logDir  string
}

func (e *fuseSessionHarness) spawnDaemonIncarnation(t *testing.T, name string, extra ...string) *daemonIncarnation {
	t.Helper()
	logDir := filepath.Join(e.workDir, "logs-"+name)
	require.NoError(t, os.MkdirAll(logDir, 0755))

	args := []string{
		"fuse",
		"--bootstrap", e.bootstrap,
		"--blob-dir", e.blobDir,
		"--mountpoint", e.mntDir,
		"--log-dir", logDir,
	}
	if e.ctlSock != "" {
		args = append(args, "--apiserver", "unix://"+e.ctlSock)
	}
	if e.supervisorSock != "" {
		args = append(args, "--supervisor-socket", "unix://"+e.supervisorSock)
	}
	args = append(args, extra...)

	d := &daemonIncarnation{
		name:    name,
		console: filepath.Join(e.workDir, name+".console.log"),
		logDir:  logDir,
	}
	cmd := exec.Command(e.nydusBin, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NYDUS_FUSE_APISERVER=") &&
			!strings.HasPrefix(entry, "NYDUS_FUSE_SUPERVISOR_SOCKET=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	d.start(t, cmd)
	return d
}

func (d *daemonIncarnation) start(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	logFile, err := os.Create(d.console)
	require.NoError(t, err)
	defer func() { require.NoError(t, logFile.Close()) }()
	if cmd.Stdout == nil {
		cmd.Stdout = logFile
	}
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	d.cmd = cmd
	d.exited = make(chan struct{})
	go func() {
		d.waitErr = cmd.Wait()
		close(d.exited)
	}()

	t.Cleanup(func() {
		if d.alive() {
			if err := d.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill %s: %v", d.name, err)
			}
			<-d.exited
		}
		if t.Failed() {
			t.Logf("--- %s console log ---\n%s", d.name, d.logCorpus())
		}
	})
}

func startHelperProcess(t *testing.T, cmd *exec.Cmd) *daemonIncarnation {
	t.Helper()
	d := &daemonIncarnation{
		name:    cmd.Args[1],
		console: filepath.Join(t.TempDir(), "helper.log"),
	}
	d.start(t, cmd)
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

func (d *daemonIncarnation) waitExit(timeout time.Duration) bool {
	select {
	case <-d.exited:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (d *daemonIncarnation) logCorpus() string {
	console, _ := os.ReadFile(d.console)
	return string(console) + util.ReadLogs(d.logDir)
}

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
	require.Eventually(t, func() bool { return util.IsMountpoint(e.mntDir) },
		20*time.Second, 200*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireUnmounted(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool { return !util.IsMountpoint(e.mntDir) },
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
	sessionID *string,
	timeout time.Duration,
	interval time.Duration,
	message string,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		info, err := requestControlInfo(e.ctlSock)
		if err != nil || info.Info.PID != uint32(daemon.cmd.Process.Pid) {
			return false
		}
		if sessionID == nil {
			return info.SessionID == nil
		}
		return info.SessionID != nil && *info.SessionID == *sessionID
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
	env.nydusBin = nydusBin
	env.workDir = t.TempDir()
	env.sourceDir = filepath.Join(env.workDir, "source")
	env.blobDir = filepath.Join(env.workDir, "blobs")
	env.mntDir = filepath.Join(env.workDir, "mnt")
	env.bootstrap = filepath.Join(env.workDir, "bootstrap.boot")

	env.ctlSock = tempSocketPath(t)
	require.NoError(t, os.MkdirAll(env.sourceDir, 0755))
	require.NoError(t, os.MkdirAll(env.mntDir, 0755))
	mntDir, err := filepath.EvalSymlinks(env.mntDir)
	require.NoError(t, err)
	env.mntDir = mntDir
	t.Cleanup(func() {
		_ = os.Remove(env.stateBase() + ".lock")
		_ = os.Remove(env.stateBase() + ".owner")
	})
	t.Cleanup(func() { util.Unmount(env.mntDir) })
	return env
}

func (e *fuseSessionHarness) stateBase() string {
	digest := sha256.Sum256([]byte(e.mntDir))
	return filepath.Join("/run/nydus/fuse", fmt.Sprint(os.Geteuid()), fmt.Sprintf("%x", digest))
}

func setupContinuityHarness(t *testing.T, protected bool) (*fuseSessionHarness, []byte) {
	t.Helper()
	env := newFuseSessionHarness(t)
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
	require.NoError(t, unix.Setxattr(
		filepath.Join(env.sourceDir, heldFileRel),
		heldFileXattrName,
		[]byte(heldFileXattrValue),
		0,
	))
	util.BuildImage(t, env.nydusBin, env.bootstrap, env.blobDir, env.sourceDir, 4096)
	if protected {
		env.supervisorSock = filepath.Join(filepath.Dir(env.ctlSock), "supervisor.sock")
		newFakeRecoveryHolder(t, env)
	}
	return env, stressSource
}

type ioStress struct {
	stopCh chan struct{}
	doneCh chan struct{}

	mu       sync.Mutex
	ops      int64
	errs     []string
	maxStall time.Duration

	crashGeneration int64
	eioByCrash      map[int64]int64
}

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
		_, added, _ := unix.ParseDirent(buf[:n], -1, nil)
		count += added
	}
}

func startIOStress(mntDir string, want []byte) *ioStress {
	s := &ioStress{
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
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
				if (errors.Is(err, unix.EIO) || errors.Is(err, unix.ECONNABORTED)) &&
					s.crashGeneration > startedAtCrash {
					s.eioByCrash[s.crashGeneration]++
					return
				}
				s.errs = append(s.errs, fmt.Sprintf("%s: %v", operation, err))
			}
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
			// Send an explicit uncached request every iteration; buffered reads,
			// stat and readdir are served from the kernel caches once warm.
			statfsGeneration := s.currentCrashGeneration()
			var statfs unix.Statfs_t
			if err := unix.Statfs(mntDir, &statfs); err != nil {
				recordError("statfs", err, statfsGeneration)
			}
			stall := time.Since(start)
			s.mu.Lock()
			s.ops++
			s.errs = append(s.errs, errs...)
			s.maxStall = max(s.maxStall, stall)
			s.mu.Unlock()
		}
	}()
	return s
}

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
	return maps.Clone(s.eioByCrash)
}

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

func (r *partialDirReader) readBatch(t *testing.T) bool {
	t.Helper()
	buf := make([]byte, 512)
	n, err := unix.Getdents(r.fd, buf)
	require.NoError(t, err)
	if n == 0 {
		return true
	}
	_, _, r.names = unix.ParseDirent(buf[:n], -1, r.names)
	return false
}

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

func newRecoveryChannel(t *testing.T) (*net.UnixConn, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	holderFile := os.NewFile(uintptr(fds[0]), "recovery-holder")
	childFile := os.NewFile(uintptr(fds[1]), "recovery-child")
	conn, err := net.FileConn(holderFile)
	require.NoError(t, holderFile.Close())
	require.NoError(t, err)
	unixConn, ok := conn.(*net.UnixConn)
	require.True(t, ok, "expected UnixConn from recovery socketpair")
	return unixConn, childFile
}

func setRecoveryDeadline(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(recoveryProtocolTimeout)))
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
	require.Equal(t, inflightJournalMagic, string(mapping[:inflightJournalVersionOffset]))
	require.Equal(t, inflightJournalVersion, binary.NativeEndian.Uint32(
		mapping[inflightJournalVersionOffset:inflightJournalCapacityOffset],
	))
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

func countInflightSlots(mapping []byte) int {
	capacity := int(binary.NativeEndian.Uint32(
		mapping[inflightJournalCapacityOffset:inflightJournalHeaderSize],
	))
	count := 0
	for index := 0; index < capacity; index++ {
		offset := inflightJournalHeaderSize + index*inflightJournalSlotSize
		if binary.NativeEndian.Uint64(mapping[offset:offset+8])&inflightSlotTagMask == inflightSlotTagInflight {
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
	if journalFD < 0 {
		beforeKill()
		require.NoError(t, daemon.cmd.Process.Kill())
		require.True(t, daemon.waitExit(30*time.Second), "the daemon did not exit after SIGKILL")
		return 0
	}
	mapping := mapInflightJournal(t, journalFD, unix.PROT_READ)
	defer func() { require.NoError(t, unix.Munmap(mapping)) }()

	deadline := time.Now().Add(200 * time.Second)
	for time.Now().Before(deadline) {
		if countInflightSlots(mapping) == 0 {
			runtime.Gosched()
			continue
		}

		require.NoError(t, daemon.cmd.Process.Signal(unix.SIGSTOP))
		time.Sleep(2 * time.Millisecond)
		published := countInflightSlots(mapping)
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
		published = countInflightSlots(mapping)
		require.Greater(t, published, 0,
			"the trapped stress request disappeared from the journal after the crash")
		return published
	}
	t.Fatal("continuous stress did not publish a FUSE request before the deadline")
	return 0
}

func readControlHTTPHeader(conn *net.UnixConn) ([]byte, error) {
	header := make([]byte, 0, 512)
	var next [1]byte
	for len(header) < 16*1024 {
		if _, err := io.ReadFull(conn, next[:]); err != nil {
			return nil, err
		}
		header = append(header, next[0])
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			return header, nil
		}
	}
	return nil, errors.New("control HTTP header exceeds 16 KiB")
}

func hasHTTPToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func dialControl(path string, timeout time.Duration) (*net.UnixConn, error) {
	deadline := time.Now().Add(timeout)
	dialer := net.Dialer{Deadline: deadline}
	raw, err := dialer.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	conn := raw.(*net.UnixConn)
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := upgradeControlClient(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func upgradeControlClient(conn *net.UnixConn) error {
	if _, err := io.WriteString(conn, "GET "+controlUpgradePath+" HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: "+controlUpgradeProtocol+"\r\n\r\n"); err != nil {
		return err
	}
	header, err := readControlHTTPHeader(conn)
	if err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), nil)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.Proto != "HTTP/1.1" || response.StatusCode != http.StatusSwitchingProtocols ||
		!hasHTTPToken(response.Header.Get("Connection"), "Upgrade") ||
		response.Header.Get("Upgrade") != controlUpgradeProtocol {
		return fmt.Errorf("invalid control HTTP upgrade response: %s", header)
	}
	return nil
}

func acceptControlHTTP(conn *net.UnixConn) error {
	header, err := readControlHTTPHeader(conn)
	if err != nil {
		return err
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		return err
	}
	if request.Proto != "HTTP/1.1" || request.Method != http.MethodGet ||
		request.RequestURI != controlUpgradePath || request.Host != "localhost" ||
		!hasHTTPToken(request.Header.Get("Connection"), "Upgrade") ||
		request.Header.Get("Upgrade") != controlUpgradeProtocol {
		return fmt.Errorf("invalid control HTTP upgrade request: %s", header)
	}
	_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+controlUpgradeProtocol+"\r\n\r\n")
	return err
}

func requestControlInfo(path string) (ctlResponse, error) {
	conn, err := dialControl(path, time.Second)
	if err != nil {
		return ctlResponse{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := writeControlFrame(conn, map[string]any{"type": "info"}); err != nil {
		return ctlResponse{}, err
	}
	responseFrame, err := readControlFrame(conn)
	if err != nil {
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
	return response.Info.PID, nil
}

func (e *fuseSessionHarness) startFakeHotUpgradeSuccessor(
	t *testing.T,
	sessionID *string,
) *daemonIncarnation {
	t.Helper()
	sessionJSON, err := json.Marshal(sessionID)
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=^TestFusePreReadyHelper$")
	cmd.Env = append(os.Environ(),
		"NYDUS_E2E_FUSE_PRE_READY_HELPER=1",
		"NYDUS_E2E_FUSE_APISERVER=unix://"+e.ctlSock,
		"NYDUS_E2E_FUSE_MOUNTPOINT="+e.mntDir,
		"NYDUS_E2E_FUSE_BOOTSTRAP="+e.bootstrap,
		"NYDUS_E2E_FUSE_SESSION_ID="+string(sessionJSON),
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	successor := startHelperProcess(t, cmd)
	ready := make(chan error, 1)
	go func() {
		// TestMain prints the nydus version before the helper test runs.
		scanner := bufio.NewScanner(stdout)
		var lines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "TRANSFERRED" {
				ready <- nil
				return
			}
			lines = append(lines, line)
		}
		ready <- fmt.Errorf("helper exited before readiness: %q", lines)
	}()
	select {
	case err := <-ready:
		require.NoError(t, err, successor.logCorpus())
	case <-time.After(10 * time.Second):
		require.FailNow(t, "pre-READY successor did not receive the Session Transfer",
			successor.logCorpus())
	}
	return successor
}

type recoveryHandleReport struct {
	Ready      bool     `json:"ready,omitempty"`
	PreNames   int      `json:"pre_names,omitempty"`
	FileSize   int      `json:"file_size,omitempty"`
	FileDigest string   `json:"file_digest,omitempty"`
	DirNames   []string `json:"dir_names,omitempty"`
}

type recoveryHandleKeeper struct {
	*daemonIncarnation
	conn *net.UnixConn
}

func startRecoveryHandleKeeper(t *testing.T, env *fuseSessionHarness) *recoveryHandleKeeper {
	t.Helper()
	conn, childFile := newRecoveryChannel(t)
	t.Cleanup(func() { _ = conn.Close() })
	defer func() { _ = childFile.Close() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFuseHeldHandleHelper$")
	cmd.Env = append(os.Environ(),
		"NYDUS_E2E_FUSE_HANDLE_HELPER=1",
		"NYDUS_E2E_FUSE_HANDLE_FILE="+filepath.Join(env.mntDir, recoveryHeldFileRel),
		"NYDUS_E2E_FUSE_HANDLE_DIR="+filepath.Join(env.mntDir, heldDirRel),
	)
	cmd.ExtraFiles = []*os.File{childFile}
	keeper := &recoveryHandleKeeper{
		daemonIncarnation: startHelperProcess(t, cmd),
		conn:              conn,
	}
	require.NoError(t, childFile.Close())

	setRecoveryDeadline(t, conn)
	var ready recoveryHandleReport
	require.NoError(t, json.NewDecoder(conn).Decode(&ready), keeper.logCorpus())
	require.True(t, ready.Ready, keeper.logCorpus())
	require.Greater(t, ready.PreNames, 0)
	require.Less(t, ready.PreNames, heldDirEntries)
	require.NoError(t, conn.SetDeadline(time.Time{}))
	return keeper
}

func (k *recoveryHandleKeeper) verify(t *testing.T, expectedFile []byte) {
	t.Helper()
	setRecoveryDeadline(t, k.conn)
	require.NoError(t, json.NewEncoder(k.conn).Encode(map[string]string{"type": "verify"}))
	var report recoveryHandleReport
	require.NoError(t, json.NewDecoder(k.conn).Decode(&report), k.logCorpus())
	require.Equal(t, len(expectedFile), report.FileSize)
	expectedDigest := sha256.Sum256(expectedFile)
	require.Equal(t, fmt.Sprintf("%x", expectedDigest), report.FileDigest)
	require.Len(t, report.DirNames, heldDirEntries)
	slices.Sort(report.DirNames)
	for i, name := range report.DirNames {
		require.Equal(t, fmt.Sprintf("entry_%04d", i), name)
	}

	require.NoError(t, k.conn.Close())
	require.True(t, k.waitExit(recoveryProtocolTimeout), k.logCorpus())
	require.NoError(t, k.waitErr, k.logCorpus())
}

func (e *fuseSessionHarness) requireRecoveredFilesystem(
	t *testing.T,
	want []byte,
	wantDev uint64,
) {
	t.Helper()
	e.requireMountIdentity(t, wantDev, "recovery replaced the FUSE mount")
	got, err := readFileRaw(filepath.Join(e.mntDir, stressFileRel))
	require.NoError(t, err)
	require.Equal(t, want, got)
	var stat unix.Stat_t
	require.NoError(t, unix.Stat(filepath.Join(e.mntDir, stressFileRel), &stat))
	require.Equal(t, int64(len(want)), stat.Size)
	entries, err := countDirEntriesRaw(filepath.Join(e.mntDir, heldDirRel))
	require.NoError(t, err)
	require.Equal(t, heldDirEntries, entries)
}

type ctlInstanceInfo struct {
	PID         uint32 `json:"pid"`
	Version     string `json:"version"`
	Mountpoint  string `json:"mountpoint"`
	ImageDigest string `json:"image_digest"`
}

type ctlResponse struct {
	Type        string           `json:"type"`
	Message     string           `json:"message,omitempty"`
	State       json.RawMessage  `json:"state,omitempty"`
	Info        *ctlInstanceInfo `json:"info,omitempty"`
	Mountpoint  string           `json:"mountpoint,omitempty"`
	ImageDigest string           `json:"image_digest,omitempty"`
	SessionID   *string          `json:"session_id,omitempty"`
}

type ctlFuseSessionState struct {
	ProtoMajor          uint32 `json:"proto_major"`
	ProtoMinor          uint32 `json:"proto_minor"`
	NegotiatedInitFlags uint64 `json:"negotiated_init_flags"`
	KernelInitFlags     uint64 `json:"kernel_init_flags"`
}

type ctlRecoveryState struct {
	Version          uint32              `json:"version"`
	SessionID        *string             `json:"session_id"`
	Mountpoint       string              `json:"mountpoint"`
	ImageDigest      string              `json:"image_digest"`
	FuseSessionState ctlFuseSessionState `json:"fuse_session_state"`
	InflightJournal  bool                `json:"inflight_journal"`
}

type recoveryBundle struct {
	SessionID string
	Metadata  []byte
	FDs       []int
}

func (b *recoveryBundle) journalFD(t *testing.T) int {
	t.Helper()
	var state ctlRecoveryState
	require.NoError(t, json.Unmarshal(b.Metadata, &state))
	require.NotNil(t, state.SessionID, "only a protected session keeps a journal")
	if !state.InflightJournal {
		return -1
	}
	require.GreaterOrEqual(t, len(b.FDs), 2, "a journal follows at least one device")
	return b.FDs[len(b.FDs)-1]
}

func (b *recoveryBundle) close() {
	for i, fd := range b.FDs {
		if fd >= 0 {
			_ = unix.Close(fd)
			b.FDs[i] = -1
		}
	}
}

type fakeRecoveryHolder struct {
	t        *testing.T
	listener *net.UnixListener
	workers  sync.WaitGroup

	mu        sync.Mutex
	bundle    *recoveryBundle
	commands  []string
	fetchHook func() error
}

func newFakeRecoveryHolder(
	t *testing.T,
	harness *fuseSessionHarness,
) *fakeRecoveryHolder {
	t.Helper()
	holder := &fakeRecoveryHolder{t: t}
	harness.holder = holder
	t.Cleanup(holder.cleanup)
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
		return 0, 0, errors.New("supervisor peer has invalid credentials")
	}
	return int(credentials.Pid), credentials.Uid, nil
}

func (h *fakeRecoveryHolder) serve() {
	for {
		conn, err := h.listener.AcceptUnix()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				h.t.Errorf("supervisor accept failed: %v", err)
			}
			return
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			defer func() { _ = conn.Close() }()
			if err := h.handle(conn); err != nil {
				h.t.Errorf("holder transaction failed: %v", err)
			}
		}()
	}
}

func (h *fakeRecoveryHolder) handle(conn *net.UnixConn) error {
	if err := conn.SetDeadline(time.Now().Add(recoveryProtocolTimeout)); err != nil {
		return err
	}
	_, peerUID, err := supervisorPeerCredentials(conn)
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
	payload, err := readRawFrame(conn)
	if err != nil {
		return err
	}
	var command struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return writeControlFrame(conn, map[string]any{"type": "error", "message": err.Error()})
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return writeControlFrame(conn, map[string]any{"type": "error", "message": "trailing command data"})
	}
	h.mu.Lock()
	h.commands = append(h.commands, command.Type)
	h.mu.Unlock()
	switch command.Type {
	case "fetch":
		h.mu.Lock()
		hook := h.fetchHook
		h.mu.Unlock()
		if hook != nil {
			if err := hook(); err != nil {
				return writeControlFrame(conn, map[string]any{"type": "error", "message": err.Error()})
			}
		}
		h.mu.Lock()
		if h.bundle == nil {
			h.mu.Unlock()
			return writeControlFrame(conn, map[string]any{"type": "empty"})
		}
		bundle, err := duplicateRecoveryBundle(h.bundle)
		h.mu.Unlock()
		if err != nil {
			return writeControlFrame(conn, map[string]any{"type": "error", "message": err.Error()})
		}
		defer bundle.close()
		if err := writeControlFrame(conn, map[string]any{"type": "transfer"}); err != nil {
			return err
		}
		if err := writeRawFrame(conn, bundle.Metadata); err != nil {
			return err
		}
		return sendRecoveryDescriptors(conn, bundle.FDs)
	case "retain":
		metadata, err := readRawFrame(conn)
		if err != nil {
			return err
		}
		fds, err := recvFDs(conn, maxTransferFDs)
		if err != nil {
			return err
		}
		stored := &recoveryBundle{SessionID: command.SessionID, Metadata: metadata, FDs: fds}
		if command.SessionID == "" {
			stored.close()
			return writeControlFrame(conn, map[string]any{"type": "error", "message": "retain requires a session ID"})
		}
		h.mu.Lock()
		if h.bundle != nil {
			h.mu.Unlock()
			stored.close()
			return writeControlFrame(conn, map[string]any{
				"type": "error", "message": "a Session Transfer is already retained",
			})
		}
		h.bundle = stored
		h.mu.Unlock()
		return writeControlFrame(conn, map[string]any{"type": "retained"})
	case "release":
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.bundle != nil && h.bundle.SessionID != command.SessionID {
			return writeControlFrame(conn, map[string]any{
				"type": "error", "message": "another session is retained",
			})
		}
		if h.bundle != nil {
			h.bundle.close()
			h.bundle = nil
		}
		return writeControlFrame(conn, map[string]any{"type": "released"})
	default:
		return writeControlFrame(conn, map[string]any{"type": "error", "message": "unknown Holder command"})
	}
}

func (h *fakeRecoveryHolder) receivedCommands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.commands)
}

func (h *fakeRecoveryHolder) requireStoredBundle() ctlRecoveryState {
	h.t.Helper()
	var metadata []byte
	require.Eventually(h.t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.bundle == nil {
			return false
		}
		metadata = slices.Clone(h.bundle.Metadata)
		return true
	}, 10*time.Second, 100*time.Millisecond,
		"the Failover-Protected Session never stored its Session Transfer in the Holder")
	var state ctlRecoveryState
	require.NoError(h.t, json.Unmarshal(metadata, &state))
	require.Equal(h.t, uint32(1), state.Version)
	require.NotNil(h.t, state.SessionID)
	require.NotEmpty(h.t, *state.SessionID)
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
		SessionID: bundle.SessionID,
		Metadata:  slices.Clone(bundle.Metadata),
	}
	for _, fd := range bundle.FDs {
		duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			bundleCopy.close()
			return nil, err
		}
		bundleCopy.FDs = append(bundleCopy.FDs, duplicate)
	}
	return bundleCopy, nil
}

func (h *fakeRecoveryHolder) requireReleased(message string) {
	h.t.Helper()
	require.Eventually(h.t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.bundle == nil && slices.Contains(h.commands, "release")
	}, 10*time.Second, 100*time.Millisecond, message)
}

func (h *fakeRecoveryHolder) restoreRetainedTransfer(bundle *recoveryBundle) {
	h.mu.Lock()
	defer h.mu.Unlock()
	require.Nil(h.t, h.bundle)
	h.bundle = bundle
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
	_, err := io.Copy(conn, bytes.NewReader(frameBytes))
	return err
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

func recvFDsExact(conn *net.UnixConn, expected int) ([]int, error) {
	fds, err := recvFDs(conn, expected)
	if err == nil && len(fds) != expected {
		closeFDs(fds)
		return nil, fmt.Errorf("received %d descriptors, expected %d", len(fds), expected)
	}
	return fds, err
}

func recvFDs(conn *net.UnixConn, maxCount int) (fds []int, err error) {
	if maxCount <= 0 {
		return nil, fmt.Errorf("invalid descriptor limit %d", maxCount)
	}
	defer func() {
		if err != nil {
			for _, fd := range fds {
				err = errors.Join(err, unix.Close(fd))
			}
			fds = nil
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
	oob := make([]byte, unix.CmsgSpace((maxCount+1)*4))
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
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	invalidControl := false
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			invalidControl = true
			continue
		}
		rights, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil {
			return fds, parseErr
		}
		fds = append(fds, rights...)
	}
	if n != 1 || payload[0] != 'F' || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return fds, errors.New("invalid descriptor transfer payload")
	}
	if invalidControl || len(messages) != 1 {
		return fds, errors.New("descriptor transfer requires one SCM_RIGHTS message")
	}
	if len(fds) == 0 || len(fds) > maxCount {
		return fds, fmt.Errorf("received %d descriptors, expected 1 to %d", len(fds), maxCount)
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

func TestRecvFDsExact(t *testing.T) {
	tests := []struct {
		name     string
		tag      byte
		sent     int
		expected int
	}{
		{name: "standalone", tag: 'F', sent: 1, expected: 1},
		{name: "protected", tag: 'F', sent: 2, expected: 2},
		{name: "wrong tag", tag: 'X', sent: 1, expected: 1},
		{name: "wrong count", tag: 'F', sent: 1, expected: 2},
		{name: "truncated rights", tag: 'F', sent: 64, expected: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receiver, senderFile := newRecoveryChannel(t)
			sender, err := net.FileConn(senderFile)
			require.NoError(t, senderFile.Close())
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, sender.Close())
				require.NoError(t, receiver.Close())
			})
			peer, sentinel := newRecoveryChannel(t)
			t.Cleanup(func() { require.NoError(t, peer.Close()) })
			rights := make([]int, tc.sent)
			for i := range rights {
				rights[i] = int(sentinel.Fd())
			}
			conn, ok := sender.(*net.UnixConn)
			require.True(t, ok)
			_, _, err = conn.WriteMsgUnix([]byte{tc.tag}, unix.UnixRights(rights...), nil)
			require.NoError(t, err)
			require.NoError(t, sentinel.Close())

			fds, err := recvFDsExact(receiver, tc.expected)
			if tc.tag == 'F' && tc.sent == tc.expected {
				require.NoError(t, err)
				require.Len(t, fds, tc.expected)
				for _, fd := range fds {
					require.NoError(t, unix.Close(fd))
				}
			} else {
				require.Error(t, err)
				require.Nil(t, fds)
			}
			setRecoveryDeadline(t, peer)
			_, err = peer.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF, "received descriptors leaked")
		})
	}
}

func tempSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nydus-sock")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "api.sock")
}

func writeCtlFrame(t *testing.T, conn net.Conn, v any) {
	t.Helper()
	require.NoError(t, writeControlFrame(conn, v))
}

func readCtlFrame(t *testing.T, conn net.Conn) ctlResponse {
	t.Helper()
	response, err := readControlFrame(conn)
	require.NoError(t, err)
	return response
}

func TestFakeRecoveryHolderProtocol(t *testing.T) {
	env := &fuseSessionHarness{supervisorSock: tempSocketPath(t)}
	holder := newFakeRecoveryHolder(t, env)
	connect := func(command string, sessionID ...string) *net.UnixConn {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: env.supervisorSock, Net: "unix"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		setRecoveryDeadline(t, conn)
		request := map[string]string{"type": command}
		if len(sessionID) > 0 {
			request["session_id"] = sessionID[0]
		}
		writeCtlFrame(t, conn, request)
		return conn
	}
	require.Equal(t, "empty", readCtlFrame(t, connect("fetch")).Type)
	require.Equal(t, "error", readCtlFrame(t, connect("unknown")).Type)

	firstPeer, firstFD := newRecoveryChannel(t)
	secondPeer, secondFD := newRecoveryChannel(t)
	t.Cleanup(func() {
		_ = firstPeer.Close()
		_ = secondPeer.Close()
		_ = firstFD.Close()
		_ = secondFD.Close()
	})
	metadata := []byte(`{"opaque":"unchanged"}`)
	require.Equal(t, "released", readCtlFrame(t, connect("release", "first")).Type,
		"releasing an empty Holder must succeed so a retry is safe")
	retain := connect("retain", "first")
	require.NoError(t, writeRawFrame(retain, metadata))
	require.NoError(t, sendRecoveryDescriptors(retain, []int{int(firstFD.Fd()), int(secondFD.Fd())}))
	require.Equal(t, "retained", readCtlFrame(t, retain).Type)
	require.NoError(t, firstFD.Close())
	require.NoError(t, secondFD.Close())

	rejectedPeer, rejectedFD := newRecoveryChannel(t)
	t.Cleanup(func() { _ = rejectedPeer.Close(); _ = rejectedFD.Close() })
	replacement := connect("retain", "second")
	require.NoError(t, writeRawFrame(replacement, []byte(`{"opaque":"replacement"}`)))
	require.NoError(t, sendRecoveryDescriptors(replacement, []int{int(rejectedFD.Fd()), int(rejectedFD.Fd())}))
	require.Equal(t, "error", readCtlFrame(t, replacement).Type)
	require.NoError(t, rejectedFD.Close())
	setRecoveryDeadline(t, rejectedPeer)
	_, err := rejectedPeer.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "rejected replacement leaked received descriptors")

	for attempt := 0; attempt < 2; attempt++ {
		fetch := connect("fetch")
		require.Equal(t, "transfer", readCtlFrame(t, fetch).Type)
		got, err := readRawFrame(fetch)
		require.NoError(t, err)
		require.Equal(t, metadata, got)
		fds, err := recvFDsExact(fetch, 2)
		require.NoError(t, err)
		closeFDs(fds)
	}
	require.Equal(t, "error", readCtlFrame(t, connect("release", "second")).Type,
		"another session must not release the retained one")
	holder.mu.Lock()
	retained := holder.bundle != nil
	holder.mu.Unlock()
	require.True(t, retained, "a rejected release dropped the retained bundle")
	require.Equal(t, "released", readCtlFrame(t, connect("release", "first")).Type)
	for _, peer := range []*net.UnixConn{firstPeer, secondPeer} {
		setRecoveryDeadline(t, peer)
		_, err := peer.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF, "release or fetch leaked descriptor copies")
	}
	require.Equal(t, "empty", readCtlFrame(t, connect("fetch")).Type,
		"only a release or explicit cleanup should make a populated Holder empty")
	require.Nil(t, holder.bundle)
}

func acceptInterruptedUpgrade(listener *net.UnixListener, info ctlResponse) (conn *net.UnixConn, err error) {
	conn, err = listener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return conn, err
	}
	if err = acceptControlHTTP(conn); err != nil {
		return conn, err
	}
	for _, expected := range []string{"info", "handoff_begin"} {
		request, readErr := readControlFrame(conn)
		if readErr != nil {
			return conn, readErr
		}
		if request.Type != expected {
			return conn, fmt.Errorf("expected startup control command %q, got %q", expected, request.Type)
		}
		if expected == "info" {
			instance := *info.Info
			instance.PID = uint32(os.Getpid())
			info.Info = &instance
			if err = writeControlFrame(conn, info); err != nil {
				return conn, err
			}
		} else if err = conn.SetDeadline(time.Now().Add(recoveryProtocolTimeout)); err != nil {
			return conn, err
		}
	}
	return conn, nil
}

type interruptedUpgradeControl struct {
	*daemonIncarnation
	protocol *net.UnixConn
}

func startInterruptedUpgradeControl(t *testing.T, path string, info ctlResponse) *interruptedUpgradeControl {
	t.Helper()
	protocol, childFile := newRecoveryChannel(t)
	t.Cleanup(func() { _ = protocol.Close() })
	defer func() { _ = childFile.Close() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFuseInterruptedUpgradeHelper$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(),
		"NYDUS_E2E_FUSE_INTERRUPTED_UPGRADE_HELPER=1",
		"NYDUS_E2E_FUSE_APISERVER=unix://"+path,
	)
	cmd.ExtraFiles = []*os.File{childFile}
	helper := &interruptedUpgradeControl{
		daemonIncarnation: startHelperProcess(t, cmd),
		protocol:          protocol,
	}
	require.NoError(t, childFile.Close())
	setRecoveryDeadline(t, protocol)
	writeCtlFrame(t, protocol, info)
	require.Equal(t, "listening", readCtlFrame(t, protocol).Type)
	return helper
}

func (c *interruptedUpgradeControl) takeConnection(t *testing.T) *net.UnixConn {
	t.Helper()
	setRecoveryDeadline(t, c.protocol)
	fds, err := recvFDsExact(c.protocol, 1)
	require.NoError(t, err)
	file := os.NewFile(uintptr(fds[0]), "interrupted-upgrade-control")
	conn, err := net.FileConn(file)
	require.NoError(t, file.Close())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	// Keep a duplicate of the stream alive until the real reader also exits.
	// EOF must not race with exit of the authenticated control peer.
	require.True(t, c.waitExit(recoveryProtocolTimeout), c.logCorpus())
	require.NoError(t, c.waitErr, c.logCorpus())
	return conn.(*net.UnixConn)
}

func TestInterruptedUpgradeControlSameConnection(t *testing.T) {
	path := tempSocketPath(t)
	sessionID := "retained-session"
	info := ctlResponse{
		Type:      "info",
		Info:      &ctlInstanceInfo{PID: 1, Mountpoint: "/mnt/image", ImageDigest: "digest"},
		SessionID: &sessionID,
	}
	helper := startInterruptedUpgradeControl(t, path, info)
	client, err := dialControl(path, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	writeCtlFrame(t, client, map[string]string{"type": "info"})
	response := readCtlFrame(t, client)
	require.Equal(t, "info", response.Type)
	require.Equal(t, sessionID, *response.SessionID)
	peerPID, peerUID, err := supervisorPeerCredentials(client)
	require.NoError(t, err)
	require.Equal(t, uint32(peerPID), response.Info.PID)
	require.Equal(t, uint32(os.Geteuid()), peerUID)
	require.Equal(t, helper.cmd.Process.Pid, peerPID)
	require.NotEqual(t, os.Getpid(), peerPID)
	pidfd, err := unix.PidfdOpen(peerPID, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(pidfd) })

	setRecoveryDeadline(t, client)
	writeCtlFrame(t, client, map[string]any{"type": "handoff_begin", "peer": info.Info})
	conn := helper.takeConnection(t)
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the authenticated control peer must have exited before EOF")
	require.NotZero(t, poll[0].Revents&unix.POLLIN)
	writeCtlFrame(t, conn, map[string]string{"type": "error", "message": "test interruption"})
	require.Equal(t, "test interruption", readCtlFrame(t, client).Message)
	require.NoError(t, conn.Close())
	_, err = readControlFrame(client)
	require.ErrorIs(t, err, io.EOF)
}

func TestFuseWithoutAPIServer(t *testing.T) {
	runProtectionMatrix(t, testFuseWithoutAPIServer)
}

func testFuseWithoutAPIServer(t *testing.T, protected bool) {
	t.Helper()
	env, source := setupContinuityHarness(t, protected)
	apiPath := env.ctlSock
	env.ctlSock = ""
	initial := env.spawnDaemonIncarnation(t, "api-off-initial")
	env.requireMounted(t, "API-off daemon failed to mount")
	handles := startRecoveryHandleKeeper(t, env)
	var sessionID *string
	if protected {
		sessionID = env.holder.requireStoredBundle().SessionID
		require.NotNil(t, sessionID)
		require.Regexp(t, `^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`, *sessionID)
		require.FileExists(t, env.stateBase()+".owner")
		require.FileExists(t, env.stateBase()+".lock")
	}
	dev := env.mountIdentity(t)
	env.requireRecoveredFilesystem(t, source, dev)
	require.NoFileExists(t, apiPath, "API-off startup created an HTTP socket")
	serving := initial
	if protected {
		require.NoError(t, initial.cmd.Process.Kill())
		require.True(t, initial.waitExit(10*time.Second), "initial daemon did not die")
		serving = env.spawnDaemonIncarnation(t, "api-off-recovered")
	}
	handles.verify(t, source)
	env.requireRecoveredFilesystem(t, source, dev)
	require.True(t, serving.alive(), serving.logCorpus())
	if protected {
		require.NoFileExists(t, apiPath, "API-off recovery created an HTTP socket")
		require.Equal(t, []string{"fetch", "retain", "fetch"}, env.holder.receivedCommands())
		require.Equal(t, sessionID, env.holder.requireStoredBundle().SessionID)
	}
	require.NoError(t, serving.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, serving.waitExit(30*time.Second), "API-off daemon ignored SIGTERM")
	require.True(t, serving.cmd.ProcessState.Success(), serving.logCorpus())
	env.requireUnmounted(t, "API-off shutdown left the mount attached")
	if protected {
		env.holder.requireReleased("API-off shutdown did not release the Holder's retention")
		require.Equal(t, []string{"fetch", "retain", "fetch", "release"}, env.holder.receivedCommands())
	}
}

func runProtectionMatrix(t *testing.T, run func(t *testing.T, protected bool)) {
	if os.Getuid() != 0 {
		t.Skip("FUSE E2E requires root")
	}
	tests := []struct {
		name      string
		protected bool
	}{
		{name: "standalone", protected: false},
		{name: "protected", protected: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { run(t, tc.protected) })
	}
}

func TestFuseHotUpgrade(t *testing.T) {
	runProtectionMatrix(t, testFuseHotUpgrade)
}

func testFuseHotUpgrade(t *testing.T, protected bool) {
	t.Helper()
	env, _ := setupContinuityHarness(t, protected)
	holder := env.holder
	heldSource, err := os.ReadFile(filepath.Join(env.sourceDir, heldFileRel))
	require.NoError(t, err)
	stressSource, err := os.ReadFile(filepath.Join(env.sourceDir, stressFileRel))
	require.NoError(t, err)

	predecessor := *env
	if os.Getenv("NYDUS_E2E_FUSE_PREDECESSOR") != "" {
		bin, err := util.LookupExecutableFromEnv("NYDUS_E2E_FUSE_PREDECESSOR", "nydus")
		require.NoError(t, err)
		predecessor.nydusBin = bin
	}
	old := predecessor.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the first daemon failed to mount")
	var sessionID *string
	if holder != nil {
		sessionID = holder.requireStoredBundle().SessionID
	}
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"the first daemon did not publish the expected protection state")
	require.FileExists(t, env.stateBase()+".owner",
		"startup did not create its mountpoint-keyed lifetime ownership lock")
	require.FileExists(t, env.stateBase()+".lock",
		"startup did not create its mountpoint-keyed startup lock")
	devOld := env.mountIdentity(t)
	util.CheckDirectoryEqual(t, env.sourceDir, env.mntDir, true)

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

	if holder == nil {
		env.supervisorSock = filepath.Join(filepath.Dir(env.ctlSock), "absent-holder.sock")
	}
	successor := env.spawnDaemonIncarnation(t, "new")
	env.requireServingSession(t, successor, sessionID, 30*time.Second, 200*time.Millisecond,
		"the successor changed the session's protection state or identity")
	if holder == nil {
		require.NoFileExists(t, env.supervisorSock)
	} else {
		require.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
			"hot upgrade replaced the Holder's retained Session Transfer")
		require.Equal(t, []string{"fetch", "retain"}, holder.receivedCommands(),
			"protected hot upgrade contacted the Holder")
	}
	env.requireMountIdentity(t, devOld,
		"the mount must not move across an fd handoff (same st_dev)")
	require.True(t, successor.alive(), "the successor exited right after the handoff")
	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "handoff complete; control socket removed")
	}, 10*time.Second, 200*time.Millisecond, "the old daemon did not log handoff completion")
	require.True(t, old.waitExit(30*time.Second),
		"the old daemon did not exit after the handoff despite having nothing left to serve")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero after the handoff: %v", old.cmd.ProcessState)

	secondHalf, err := io.ReadAll(held)
	require.NoError(t, err)
	require.Len(t, secondHalf, heldFileSize/2)
	require.True(t, bytes.Equal(heldSource[heldFileSize/2:], secondHalf),
		"post-upgrade read through the held fd differs from the source")
	require.NoError(t, held.Close())

	heldDir.readRest(t)
	heldDir.close()
	require.Len(t, heldDir.names, heldDirEntries,
		"the directory handle did not list every entry after handoff")
	slices.Sort(heldDir.names)
	for i, name := range heldDir.names {
		require.Equal(t, fmt.Sprintf("entry_%04d", i), name, "unexpected directory entry")
	}

	util.CheckDirectoryEqual(t, env.sourceDir, env.mntDir, true)
	_, err = os.Stat(env.ctlSock)
	require.NoError(t, err, "the successor did not re-publish the control socket")

	ops, errs, maxStall := stress.stop()
	t.Logf("stress: %d iterations across hot upgrade, max stall %v", ops, maxStall)
	require.Greater(t, ops, int64(0), "the stress loop never completed an iteration")
	require.Empty(t, errs, "IO errors during hot upgrade: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall,
		"a stress iteration stalled for %v — the handoff pause is not bounded", maxStall)

	shutdownHeld, err := os.Open(filepath.Join(env.mntDir, heldFileRel))
	require.NoError(t, err)
	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the final daemon ignored SIGTERM")
	require.True(t, successor.cmd.ProcessState.Success(),
		"the final daemon exited non-zero on SIGTERM: %v", successor.cmd.ProcessState)
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
	// The Holder's release ends the detached connection before the client
	// handle closes; otherwise its FUSE RELEASE has no serving daemon and can
	// block indefinitely.
	if holder != nil {
		holder.requireReleased("the final daemon's shutdown did not release the Holder's retention")
		require.Equal(t, []string{"fetch", "retain", "release"}, holder.receivedCommands())
	}
	_ = shutdownHeld.Close()
}

func TestFusePreReadyRollback(t *testing.T) {
	runProtectionMatrix(t, testFusePreReadyRollback)
}

func testFusePreReadyRollback(t *testing.T, protected bool) {
	t.Helper()
	env, stressSource := setupContinuityHarness(t, protected)

	old := env.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the daemon failed to mount")
	var sessionID *string
	if env.holder != nil {
		sessionID = env.holder.requireStoredBundle().SessionID
	}
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"the daemon did not publish the expected protection state")
	devOld := env.mountIdentity(t)
	stress := startIOStress(env.mntDir, stressSource)

	fakeSuccessor := env.startFakeHotUpgradeSuccessor(t, sessionID)

	// The old daemon is paused now; the kernel queues requests. Give the
	// stress loop time to pile a few up, then "crash" before reporting ready:
	// close our fd copy and the control connection (EOF).
	time.Sleep(2 * time.Second)
	require.NoError(t, fakeSuccessor.cmd.Process.Kill())
	require.True(t, fakeSuccessor.waitExit(recoveryProtocolTimeout))
	require.Error(t, fakeSuccessor.waitErr)

	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "resuming service")
	}, 15*time.Second, 200*time.Millisecond,
		"the old daemon did not resume after the successor died")
	require.True(t, old.alive(), "the old daemon must survive an aborted handoff")
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"rollback changed the session's protection state or identity")
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
	util.CheckDirectoryEqual(t, env.sourceDir, env.mntDir, true)

	successor := env.spawnDaemonIncarnation(t, "new")
	env.requireServingSession(t, successor, sessionID, 30*time.Second, 200*time.Millisecond,
		"upgrade after rollback changed the session's protection state or identity")
	if env.holder != nil {
		require.Equal(t, sessionID, env.holder.requireStoredBundle().SessionID,
			"upgrade after rollback replaced the Holder's retained Session Transfer")
		require.Equal(t, []string{"fetch", "retain"}, env.holder.receivedCommands(),
			"protected hot upgrade contacted the Holder")
	}
	require.True(t, old.waitExit(30*time.Second), "the old daemon did not exit")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero: %v", old.cmd.ProcessState)
	util.CheckDirectoryEqual(t, env.sourceDir, env.mntDir, true)

	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the successor ignored SIGTERM")
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
}

func TestFuseInterruptedUpgradeHelper(t *testing.T) {
	if os.Getenv("NYDUS_E2E_FUSE_INTERRUPTED_UPGRADE_HELPER") != "1" {
		t.Skip("helper process for interrupted-upgrade tests")
	}
	file := os.NewFile(uintptr(recoveryInheritedFD), "interrupted-upgrade-protocol")
	protocol, err := net.FileConn(file)
	require.NoError(t, file.Close())
	require.NoError(t, err)
	defer func() { _ = protocol.Close() }()
	channel := protocol.(*net.UnixConn)
	setRecoveryDeadline(t, channel)
	info := readCtlFrame(t, channel)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: strings.TrimPrefix(os.Getenv("NYDUS_E2E_FUSE_APISERVER"), "unix://"), Net: "unix",
	})
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	writeCtlFrame(t, channel, map[string]string{"type": "listening"})
	conn, err := acceptInterruptedUpgrade(listener, info)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	control, err := conn.File()
	require.NoError(t, err)
	defer func() { _ = control.Close() }()
	require.NoError(t, sendRecoveryDescriptors(channel, []int{int(control.Fd())}))
}

func TestFusePreReadyHelper(t *testing.T) {
	if os.Getenv("NYDUS_E2E_FUSE_PRE_READY_HELPER") != "1" {
		t.Skip("helper process for TestFusePreReadyRollback")
	}

	mountpoint, err := filepath.EvalSymlinks(os.Getenv("NYDUS_E2E_FUSE_MOUNTPOINT"))
	require.NoError(t, err)
	imageBytes, err := os.ReadFile(os.Getenv("NYDUS_E2E_FUSE_BOOTSTRAP"))
	require.NoError(t, err)
	imageDigest := sha256.Sum256(imageBytes)
	conn, err := dialControl(strings.TrimPrefix(os.Getenv("NYDUS_E2E_FUSE_APISERVER"), "unix://"), 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	var sessionID *string
	require.NoError(t, json.Unmarshal([]byte(os.Getenv("NYDUS_E2E_FUSE_SESSION_ID")), &sessionID))

	writeCtlFrame(t, conn, map[string]string{"type": "info"})
	info := readCtlFrame(t, conn)
	require.Equal(t, "info", info.Type)
	require.NotNil(t, info.Info)
	require.Equal(t, mountpoint, info.Info.Mountpoint)
	require.Equal(t, fmt.Sprintf("%x", imageDigest), info.Info.ImageDigest)
	require.Equal(t, sessionID, info.SessionID)
	setRecoveryDeadline(t, conn)
	writeCtlFrame(t, conn, map[string]any{
		"type": "handoff_begin",
		"peer": ctlInstanceInfo{
			PID:         uint32(os.Getpid()),
			Version:     "e2e-pre-ready-successor",
			Mountpoint:  mountpoint,
			ImageDigest: fmt.Sprintf("%x", imageDigest),
		},
	})
	response := readCtlFrame(t, conn)
	require.Equal(t, "handoff_transfer", response.Type,
		"pre-READY successor expected a Session Transfer, got %q: %s",
		response.Type, response.Message)
	metadata, err := readRawFrame(conn)
	require.NoError(t, err)
	require.NotEmpty(t, metadata)
	var state ctlRecoveryState
	require.NoError(t, json.Unmarshal(metadata, &state))
	require.Equal(t, sessionID, state.SessionID)
	require.Equal(t, mountpoint, state.Mountpoint)
	require.Equal(t, fmt.Sprintf("%x", imageDigest), state.ImageDigest)
	require.Equal(t, uint32(7), state.FuseSessionState.ProtoMajor)
	require.NotZero(t, state.FuseSessionState.ProtoMinor)
	fds, err := recvFDs(conn, maxTransferFDs)
	require.NoError(t, err)
	defer closeFDs(fds)
	devices := fds
	if sessionID == nil {
		require.False(t, state.InflightJournal)
		require.Len(t, devices, 1)
	} else if state.InflightJournal {
		require.GreaterOrEqual(t, len(fds), 2)
		devices = fds[:len(fds)-1]
		journal := mapInflightJournal(t, fds[len(fds)-1], unix.PROT_READ)
		require.NoError(t, unix.Munmap(journal))
	}
	var fuseDevice unix.Stat_t
	require.NoError(t, unix.Stat("/dev/fuse", &fuseDevice))
	for _, fd := range devices {
		var received unix.Stat_t
		require.NoError(t, unix.Fstat(fd, &received))
		require.Equal(t, uint32(unix.S_IFCHR), received.Mode&unix.S_IFMT)
		require.Equal(t, fuseDevice.Rdev, received.Rdev)
	}

	_, err = fmt.Fprintln(os.Stdout, "TRANSFERRED")
	require.NoError(t, err)
	select {}
}

func TestFuseHeldHandleHelper(t *testing.T) {
	if os.Getenv("NYDUS_E2E_FUSE_HANDLE_HELPER") != "1" {
		t.Skip("helper process for TestFuseFailoverMatrix")
	}

	protocol := os.NewFile(uintptr(recoveryInheritedFD), "held-handle-protocol")
	require.NotNil(t, protocol)
	defer func() { _ = protocol.Close() }()

	fileFD, err := unix.Open(
		os.Getenv("NYDUS_E2E_FUSE_HANDLE_FILE"),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	require.NoError(t, err)
	defer func() { _ = unix.Close(fileFD) }()
	heldDir := openPartialDirReader(t, os.Getenv("NYDUS_E2E_FUSE_HANDLE_DIR"))
	require.False(t, heldDir.readBatch(t), "the held directory was exhausted before recovery")
	require.NoError(t, json.NewEncoder(protocol).Encode(recoveryHandleReport{
		Ready:    true,
		PreNames: len(heldDir.names),
	}))

	var command map[string]string
	require.NoError(t, json.NewDecoder(protocol).Decode(&command))
	require.Equal(t, "verify", command["type"])
	fileBytes, err := readAtRaw(fileFD, stressFileSize)
	require.NoError(t, err)
	heldDir.readRest(t)
	heldDir.close()
	fileDigest := sha256.Sum256(fileBytes)
	require.NoError(t, json.NewEncoder(protocol).Encode(recoveryHandleReport{
		FileSize:   len(fileBytes),
		FileDigest: fmt.Sprintf("%x", fileDigest),
		DirNames:   heldDir.names,
	}))
}

func TestFuseFailoverMatrix(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("FUSE failover acceptance test requires root")
	}

	t.Run("matrix", testFuseFailoverMatrix)
	t.Run("live-owner-missing-control", func(t *testing.T) {
		testFuseLiveOwnerWithoutControl(t, false)
	})
	t.Run("live-owner-unresponsive-control", func(t *testing.T) {
		testFuseLiveOwnerWithoutControl(t, true)
	})
	t.Run("discovery-interrupted-by-crash", testFuseDiscoveryInterruptedByCrash)
	t.Run("recovery-retry-and-concurrent-starts", testFuseRecoveryRetryAndConcurrentStarts)
}

func testFuseFailoverMatrix(t *testing.T) {
	env, stressSource := setupContinuityHarness(t, true)
	holder := env.holder
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
	stress := startIOStress(env.mntDir, stressSource)

	upgraded := env.spawnDaemonIncarnation(t, "matrix-upgraded")
	env.requireServingSession(t, upgraded, sessionID, 30*time.Second, 200*time.Millisecond,
		"the hot-upgrade successor did not publish the original Session Identity")
	require.True(t, initial.waitExit(30*time.Second),
		"the initial daemon did not exit after hot upgrade")
	require.True(t, initial.cmd.ProcessState.Success(),
		"the initial daemon exited non-zero after hot upgrade")
	require.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
		"hot upgrade replaced the stored Session Transfer")
	require.Equal(t, []string{"fetch", "retain"}, holder.receivedCommands(),
		"protected hot upgrade contacted the Holder")
	env.requireRecoveredFilesystem(t, stressSource, mountDev)

	crashGenerations := make([]int64, 0, 2)
	recovered := upgraded
	for attempt := 1; attempt <= 2; attempt++ {
		journaled := killWithJournaledStressRequest(t, recovered, held.journalFD(t), func() {
			crashGenerations = append(crashGenerations, stress.markCrash())
		})
		env.requireControlUnavailable(t, "the crashed daemon's control endpoint still answers")
		t.Logf("crash %d retained %d published journal entries", attempt, journaled)
		recovered = env.spawnDaemonIncarnation(t, fmt.Sprintf("matrix-recovery-%d", attempt))
		env.requireServingSession(t, recovered, sessionID, 30*time.Second, 100*time.Millisecond,
			"recovery did not publish the retained Session Identity")
		require.True(t, recovered.alive(), recovered.logCorpus())
		env.requireRecoveredFilesystem(t, stressSource, mountDev)
	}
	heldHandles.verify(t, stressSource)
	util.CheckDirectoryEqual(t, env.sourceDir, env.mntDir, true)

	ops, errs, maxStall := stress.stop()
	eioByCrash := stress.failoverEIOs()
	t.Logf("failover matrix stress: %d iterations, EIOs by crash %v, max stall %v",
		ops, eioByCrash, maxStall)
	require.Greater(t, ops, int64(0))
	require.Empty(t, errs, "unexpected IO errors across the failover matrix: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall)
	require.Len(t, crashGenerations, 2)
	for _, crash := range crashGenerations {
		require.LessOrEqual(t, eioByCrash[crash], int64(1),
			"at most one stress operation may observe an error spanning crash %d", crash)
	}

	held.close()
	require.True(t, recovered.alive(),
		"dropping holder descriptor copies tore down the recovered daemon")
	require.True(t, util.IsMountpoint(env.mntDir),
		"dropping holder descriptor copies unmounted the FUSE session")

	shutdownBundle := holder.requireStoredBundleCopy()
	require.NoError(t, recovered.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, recovered.waitExit(30*time.Second),
		"the second recovery ignored explicit shutdown")
	require.True(t, recovered.cmd.ProcessState.Success(),
		"the second recovery exited non-zero on explicit shutdown")
	env.requireUnmounted(t,
		"explicit shutdown did not unmount while the fake holder retained descriptor copies")
	holder.requireReleased("explicit shutdown did not release the Holder's retention")

	holder.restoreRetainedTransfer(shutdownBundle)
	stale := env.spawnDaemonIncarnation(t, "matrix-stale-retention")
	require.True(t, stale.waitExit(45*time.Second), "stale retention was not rejected")
	require.False(t, stale.cmd.ProcessState.Success(), "clean shutdown incorrectly authorized recovery")
	env.requireUnmounted(t, "stale Holder retention was treated as permission for a fresh mount")
	require.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
		"startup silently replaced a stale retained Session Transfer")

	holder.closeRetainedTransfer()
	fresh := env.spawnDaemonIncarnation(t, "matrix-fresh-after-cleanup")
	env.requireMounted(t, "explicit Holder cleanup did not permit a fresh start")
	newSessionID := holder.requireStoredBundle().SessionID
	require.NotEqual(t, sessionID, newSessionID)
	env.requireServingSession(t, fresh, newSessionID, 30*time.Second, 100*time.Millisecond,
		"fresh start after explicit cleanup did not publish its new Session Identity")
	require.NoError(t, fresh.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, fresh.waitExit(30*time.Second))
	env.requireUnmounted(t, "fresh start did not shut down cleanly")
	holder.requireReleased("the fresh session's shutdown did not release the Holder's retention")
}

func testFuseLiveOwnerWithoutControl(t *testing.T, unresponsive bool) {
	env, source := setupContinuityHarness(t, true)
	old := env.spawnDaemonIncarnation(t, "live-owner")
	env.requireMounted(t, "the protected daemon failed to mount")
	sessionID := env.holder.requireStoredBundle().SessionID
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"the protected daemon did not publish control")
	dev := env.mountIdentity(t)
	commands := env.holder.receivedCommands()
	hiddenSocket := env.ctlSock + ".hidden"
	require.NoError(t, os.Rename(env.ctlSock, hiddenSocket))
	t.Cleanup(func() { _ = os.Rename(hiddenSocket, env.ctlSock) })

	var listener *net.UnixListener
	var accepted chan *net.UnixConn
	if unresponsive {
		var err error
		listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: env.ctlSock, Net: "unix"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })
		accepted = make(chan *net.UnixConn, 1)
		go func() {
			conn, _ := listener.AcceptUnix()
			accepted <- conn
		}()
	}
	attempt := env.spawnDaemonIncarnation(t, "blocked-by-live-owner")
	if unresponsive {
		select {
		case conn := <-accepted:
			require.NotNil(t, conn)
			defer func() { _ = conn.Close() }()
		case <-time.After(10 * time.Second):
			require.FailNow(t, "successor never probed the unresponsive control endpoint")
		}
	}
	require.True(t, attempt.waitExit(45*time.Second),
		"a live owner with unavailable control must fail within the protocol deadline")
	require.False(t, attempt.cmd.ProcessState.Success(), "a second reader was started beside a live owner")
	require.True(t, old.alive(), "the original reader was killed by the failed start")
	require.Equal(t, commands, env.holder.receivedCommands(),
		"control failure must not fetch a retained copy while the original reader lives")
	info, err := requestControlInfo(hiddenSocket)
	require.NoError(t, err)
	require.Equal(t, uint32(old.cmd.Process.Pid), info.Info.PID)
	env.requireRecoveredFilesystem(t, source, dev)

	if listener != nil {
		require.NoError(t, listener.Close())
	}
	require.NoError(t, os.Rename(hiddenSocket, env.ctlSock))
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"restoring the socket did not expose the original reader")
	require.NoError(t, old.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, old.waitExit(30*time.Second))
	env.requireUnmounted(t, "the original reader did not shut down")
}

func testFuseDiscoveryInterruptedByCrash(t *testing.T) {
	env, source := setupContinuityHarness(t, true)
	old := env.spawnDaemonIncarnation(t, "discovered-owner")
	env.requireMounted(t, "the protected daemon failed to mount")
	sessionID := env.holder.requireStoredBundle().SessionID
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"the protected daemon did not publish control")
	dev := env.mountIdentity(t)
	info, err := requestControlInfo(env.ctlSock)
	require.NoError(t, err)
	commands := env.holder.receivedCommands()

	require.NoError(t, os.Rename(env.ctlSock, env.ctlSock+".hidden"))
	proxy := startInterruptedUpgradeControl(t, env.ctlSock, info)
	attempt := env.spawnDaemonIncarnation(t, "interrupted-upgrade")
	handoffConn := proxy.takeConnection(t)
	require.True(t, old.alive(), "predecessor died before the selected upgrade began")
	require.Equal(t, commands, env.holder.receivedCommands(), "selected hot upgrade contacted the Holder")
	require.NoError(t, old.cmd.Process.Kill())
	require.True(t, old.waitExit(30*time.Second))
	// Both the authenticated control peer and the owner are now dead. Expose
	// EOF only after pidfd exit and lifetime-lock release are observable.
	require.NoError(t, handoffConn.Close())
	env.requireServingSession(t, attempt, sessionID, 30*time.Second, 100*time.Millisecond,
		"the selected upgrade did not recover in the same launch after the predecessor crash")
	require.True(t, attempt.alive(), "the same-launch recovery exited after publishing control")
	require.Equal(t, append(commands, "fetch"), env.holder.receivedCommands())
	env.requireRecoveredFilesystem(t, source, dev)
	require.NoError(t, attempt.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, attempt.waitExit(30*time.Second))
	require.True(t, attempt.cmd.ProcessState.Success())
	env.requireUnmounted(t, "recovered reader did not shut down")
}

func testFuseRecoveryRetryAndConcurrentStarts(t *testing.T) {
	env, source := setupContinuityHarness(t, true)
	old := env.spawnDaemonIncarnation(t, "retry-original")
	env.requireMounted(t, "the protected daemon failed to mount")
	holder := env.holder
	sessionID := holder.requireStoredBundle().SessionID
	env.requireServingSession(t, old, sessionID, 10*time.Second, 100*time.Millisecond,
		"the protected daemon did not publish control")
	dev := env.mountIdentity(t)
	commands := holder.receivedCommands()
	require.NoError(t, old.cmd.Process.Kill())
	require.True(t, old.waitExit(30*time.Second))

	holder.mu.Lock()
	holder.fetchHook = func() error { return errors.New("injected fetch rejection") }
	holder.mu.Unlock()
	rejected := env.spawnDaemonIncarnation(t, "rejected-recovery")
	require.True(t, rejected.waitExit(45*time.Second))
	require.False(t, rejected.cmd.ProcessState.Success(), "Holder rejection was interpreted as Empty")
	require.Equal(t, append(commands, "fetch"), holder.receivedCommands())
	require.Equal(t, sessionID, holder.requireStoredBundle().SessionID)
	env.requireControlUnavailable(t, "rejected recovery published a reader")

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFetch := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFetch)
	holder.mu.Lock()
	holder.fetchHook = func() error {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return nil
		case <-time.After(recoveryProtocolTimeout):
			return errors.New("test did not release blocked fetch")
		}
	}
	holder.mu.Unlock()
	first := env.spawnDaemonIncarnation(t, "concurrent-recovery-1")
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		require.FailNow(t, "retry did not fetch the retained session")
	}
	second := env.spawnDaemonIncarnation(t, "concurrent-recovery-2")
	releaseFetch()

	var serving *daemonIncarnation
	require.Eventually(t, func() bool {
		pid, err := controlOwnerPID(env.ctlSock)
		if err != nil {
			return false
		}
		if pid == uint32(first.cmd.Process.Pid) && first.alive() && !second.alive() {
			serving = first
		} else if pid == uint32(second.cmd.Process.Pid) && second.alive() && !first.alive() {
			serving = second
		}
		return serving != nil
	}, 45*time.Second, 100*time.Millisecond,
		"concurrent starts did not converge to exactly one serving incarnation")
	require.Equal(t, append(commands, "fetch", "fetch"), holder.receivedCommands(),
		"the second concurrent start fetched a second reader instead of serializing with recovery")
	env.requireServingSession(t, serving, sessionID, 10*time.Second, 100*time.Millisecond,
		"concurrent startup changed the retained Session Identity")
	env.requireRecoveredFilesystem(t, source, dev)
	require.NoError(t, serving.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, serving.waitExit(30*time.Second))
	env.requireUnmounted(t, "the final concurrent-start reader did not shut down")
}
