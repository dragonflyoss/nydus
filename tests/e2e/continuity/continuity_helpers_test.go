package continuity

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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	testenv "github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	heldFileRel        = "upgrade/held_8m.bin"
	heldFileSize       = 8 << 20
	heldFileXattrName  = "user.continuity"
	heldFileXattrValue = "held-across-handoff"

	stressFileRel  = "upgrade/stress_64k.bin"
	stressFileSize = 64 << 10

	heldDirRel     = "upgrade/dirmany"
	heldDirEntries = 1024

	maxUpgradeStall        = 20 * time.Second
	controlProtocolTimeout = 10 * time.Second
	controlUpgradeProtocol = "nydus-fuse-control/1"
)

type fuseSessionHarness struct {
	nydusBin  string
	workDir   string
	sourceDir string
	blobDir   string
	mntDir    string
	bootstrap string
	ctlSock   string
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
	args = append(args, extra...)

	d := &daemonIncarnation{
		name:    name,
		console: filepath.Join(e.workDir, name+".console.log"),
		logDir:  logDir,
	}
	cmd := exec.Command(e.nydusBin, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NYDUS_FUSE_APISERVER=") {
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
		name:    "pre-ready-successor",
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
	return string(console) + mount.ReadLogs(d.logDir)
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
	require.Eventually(t, func() bool { return mount.IsMountpoint(e.mntDir) },
		20*time.Second, 200*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireUnmounted(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool { return !mount.IsMountpoint(e.mntDir) },
		10*time.Second, 200*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireServingSession(
	t *testing.T,
	daemon *daemonIncarnation,
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
		return info.SessionID == nil
	}, timeout, interval, message)
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
	env.nydusBin = testenv.Nydus(t)
	env.workDir = testenv.WorkDir(t)
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
	t.Cleanup(func() { mount.Unmount(env.mntDir) })
	return env
}

func (e *fuseSessionHarness) stateBase() string {
	digest := sha256.Sum256([]byte(e.mntDir))
	return filepath.Join("/run/nydus/fuse", fmt.Sprint(os.Geteuid()), fmt.Sprintf("%x", digest))
}

func setupContinuityHarness(t *testing.T) (*fuseSessionHarness, []byte) {
	t.Helper()
	mount.FUSE{}.Require(t)
	env := newFuseSessionHarness(t)
	stressSource := bytes.Repeat([]byte("nydus-upgrade\n"), stressFileSize/14+1)
	stressSource = stressSource[:stressFileSize]
	stressPath := filepath.Join(env.sourceDir, stressFileRel)
	require.NoError(t, os.MkdirAll(filepath.Dir(stressPath), 0755))
	require.NoError(t, os.WriteFile(stressPath, stressSource, 0644))
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
	layout, err := fixture.LayoutByName("zstd-4k")
	require.NoError(t, err)
	fixture.BuildInto(t, env.blobDir, env.bootstrap, env.sourceDir, layout)
	return env, stressSource
}

type ioStress struct {
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once

	mu       sync.Mutex
	ops      int64
	errs     []string
	maxStall time.Duration
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

func startIOStress(t *testing.T, mntDir string, want []byte) *ioStress {
	t.Helper()
	s := &ioStress{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	t.Cleanup(func() { s.stopOnce.Do(func() { close(s.stopCh) }) })
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
			got, err := readFileRaw(filePath)
			if err != nil {
				errs = append(errs, fmt.Sprintf("read %s: %v", stressFileRel, err))
			} else if !bytes.Equal(want, got) {
				errs = append(errs, fmt.Sprintf("read %s: content mismatch", stressFileRel))
			}
			var stat unix.Stat_t
			if err := unix.Stat(filePath, &stat); err != nil {
				errs = append(errs, fmt.Sprintf("stat %s: %v", stressFileRel, err))
			} else if stat.Size != int64(len(want)) {
				errs = append(errs, fmt.Sprintf("stat %s: size %d, want %d",
					stressFileRel, stat.Size, len(want)))
			}
			entries, err := countDirEntriesRaw(dirPath)
			if err != nil {
				errs = append(errs, fmt.Sprintf("readdir %s: %v", heldDirRel, err))
			} else if entries != heldDirEntries {
				errs = append(errs, fmt.Sprintf("readdir %s: %d entries, want %d",
					heldDirRel, entries, heldDirEntries))
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

func (s *ioStress) stop(t *testing.T) (int64, []string, time.Duration) {
	t.Helper()
	s.stopOnce.Do(func() { close(s.stopCh) })
	select {
	case <-s.doneCh:
	case <-time.After(maxUpgradeStall):
		t.Fatal("stress reads did not resume within the continuity deadline")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops, s.errs, s.maxStall
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

func newControlChannel(t *testing.T) (*net.UnixConn, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	parentFile := os.NewFile(uintptr(fds[0]), "control-parent")
	childFile := os.NewFile(uintptr(fds[1]), "control-child")
	conn, err := net.FileConn(parentFile)
	require.NoError(t, parentFile.Close())
	require.NoError(t, err)
	unixConn, ok := conn.(*net.UnixConn)
	require.True(t, ok, "expected UnixConn from control socketpair")
	return unixConn, childFile
}

func setControlDeadline(t assertionTB, conn *net.UnixConn) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(controlProtocolTimeout)))
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
	if _, err := io.WriteString(conn, "GET /fuse/handoff HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: "+controlUpgradeProtocol+"\r\n\r\n"); err != nil {
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

func (e *fuseSessionHarness) startFakeHotUpgradeSuccessor(t *testing.T) *daemonIncarnation {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"NYDUS_E2E_FUSE_PRE_READY_HELPER=1",
		"NYDUS_E2E_FUSE_APISERVER=unix://"+e.ctlSock,
		"NYDUS_E2E_FUSE_MOUNTPOINT="+e.mntDir,
		"NYDUS_E2E_FUSE_BOOTSTRAP="+e.bootstrap,
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	successor := startHelperProcess(t, cmd)
	ready := make(chan error, 1)
	go func() {
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

func (e *fuseSessionHarness) requireFilesystem(
	t *testing.T,
	want []byte,
	wantDev uint64,
) {
	t.Helper()
	e.requireMountIdentity(t, wantDev, "the FUSE mount was replaced")
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

type ctlTransferState struct {
	Version          uint32              `json:"version"`
	Mountpoint       string              `json:"mountpoint"`
	ImageDigest      string              `json:"image_digest"`
	FuseSessionState ctlFuseSessionState `json:"fuse_session_state"`
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

func recvFDsExact(conn *net.UnixConn, expected int) (fds []int, err error) {
	if expected <= 0 {
		return nil, fmt.Errorf("invalid expected fd count %d", expected)
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

func tempSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nydus-sock")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "api.sock")
}

func writeCtlFrame(t assertionTB, conn net.Conn, v any) {
	t.Helper()
	require.NoError(t, writeControlFrame(conn, v))
}

func readCtlFrame(t assertionTB, conn net.Conn) ctlResponse {
	t.Helper()
	response, err := readControlFrame(conn)
	require.NoError(t, err)
	return response
}

func testFuseLiveOwnerWithoutControl(t *testing.T, unresponsive bool) {
	env, source := setupContinuityHarness(t)
	old := env.spawnDaemonIncarnation(t, "live-owner")
	env.requireMounted(t, "the daemon failed to mount")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"the daemon did not publish control")
	dev := env.mountIdentity(t)
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
	info, err := requestControlInfo(hiddenSocket)
	require.NoError(t, err)
	require.Equal(t, uint32(old.cmd.Process.Pid), info.Info.PID)
	env.requireFilesystem(t, source, dev)

	if listener != nil {
		require.NoError(t, listener.Close())
	}
	require.NoError(t, os.Rename(hiddenSocket, env.ctlSock))
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"restoring the socket did not expose the original reader")
	require.NoError(t, old.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, old.waitExit(30*time.Second))
	env.requireUnmounted(t, "the original reader did not shut down")
}
