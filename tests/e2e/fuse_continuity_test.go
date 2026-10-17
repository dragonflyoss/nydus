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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	var b strings.Builder
	b.Write(readFileOrEmpty(d.console))
	if d.logDir == "" {
		return b.String()
	}
	entries, _ := os.ReadDir(d.logDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			b.Write(readFileOrEmpty(filepath.Join(d.logDir, entry.Name())))
		}
	}
	return b.String()
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
	require.Eventually(t, func() bool { return isMountpoint(e.mntDir) },
		20*time.Second, 200*time.Millisecond, message)
}

func (e *fuseSessionHarness) requireUnmounted(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool { return !isMountpoint(e.mntDir) },
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
	env.nydusBin = lookupBinFromEnv(t, "NYDUS_BIN", "nydus")
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
	t.Cleanup(func() { unmountFuse(env.mntDir) })
	return env
}

func (e *fuseSessionHarness) stateBase() string {
	digest := sha256.Sum256([]byte(e.mntDir))
	return filepath.Join("/tmp", fmt.Sprintf("nydus-fuse-%d", os.Geteuid()), fmt.Sprintf("%x", digest))
}

func setupContinuityHarness(t *testing.T) (*fuseSessionHarness, []byte) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("FUSE E2E requires root")
	}
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
	buildNydusFSImageToDir(t, env.nydusBin, env.bootstrap, env.blobDir, env.sourceDir, 4096)
	return env, stressSource
}

type ioStress struct {
	stopCh chan struct{}
	doneCh chan struct{}

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

func startIOStress(mntDir string, want []byte) *ioStress {
	s := &ioStress{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
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

func (s *ioStress) stop() (int64, []string, time.Duration) {
	close(s.stopCh)
	<-s.doneCh
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

func setControlDeadline(t *testing.T, conn *net.UnixConn) {
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
	if _, err := io.WriteString(conn, "GET /fuse/control HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: "+controlUpgradeProtocol+"\r\n\r\n"); err != nil {
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestFusePreReadyHelper$")
	cmd.Env = append(os.Environ(),
		"NYDUS_FUSE_PRE_READY_SUCCESSOR_HELPER=1",
		"NYDUS_FUSE_APISERVER=unix://"+e.ctlSock,
		"NYDUS_FUSE_MOUNTPOINT="+e.mntDir,
		"NYDUS_FUSE_BOOTSTRAP="+e.bootstrap,
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	successor := startHelperProcess(t, cmd)
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

func TestRecvFDsExact(t *testing.T) {
	tests := []struct {
		name     string
		tag      byte
		sent     int
		expected int
	}{
		{name: "connection", tag: 'F', sent: 1, expected: 1},
		{name: "wrong tag", tag: 'X', sent: 1, expected: 1},
		{name: "wrong count", tag: 'F', sent: 2, expected: 1},
		{name: "truncated rights", tag: 'F', sent: 64, expected: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receiver, senderFile := newControlChannel(t)
			sender, err := net.FileConn(senderFile)
			require.NoError(t, senderFile.Close())
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, sender.Close())
				require.NoError(t, receiver.Close())
			})
			peer, sentinel := newControlChannel(t)
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
			setControlDeadline(t, peer)
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

func TestFuseWithoutAPIServer(t *testing.T) {
	env, source := setupContinuityHarness(t)
	apiPath := env.ctlSock
	env.ctlSock = ""
	initial := env.spawnDaemonIncarnation(t, "api-off-initial")
	env.requireMounted(t, "API-off daemon failed to mount")
	require.FileExists(t, env.stateBase()+".owner")
	require.FileExists(t, env.stateBase()+".lock")
	dev := env.mountIdentity(t)
	env.requireFilesystem(t, source, dev)
	require.NoFileExists(t, apiPath, "API-off startup created an HTTP socket")
	require.True(t, initial.alive(), initial.logCorpus())
	require.NoError(t, initial.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, initial.waitExit(30*time.Second), "API-off daemon ignored SIGTERM")
	require.True(t, initial.cmd.ProcessState.Success(), initial.logCorpus())
	env.requireUnmounted(t, "API-off shutdown left the mount attached")
}

func TestFuseHotUpgrade(t *testing.T) {
	env, _ := setupContinuityHarness(t)
	heldSource, err := os.ReadFile(filepath.Join(env.sourceDir, heldFileRel))
	require.NoError(t, err)
	stressSource, err := os.ReadFile(filepath.Join(env.sourceDir, stressFileRel))
	require.NoError(t, err)

	predecessor := *env
	if os.Getenv("NYDUS_FUSE_PREDECESSOR_BIN") != "" {
		predecessor.nydusBin = lookupBinFromEnv(t, "NYDUS_FUSE_PREDECESSOR_BIN", "nydus")
	}
	old := predecessor.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the first daemon failed to mount")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"the first daemon did not publish its control endpoint")
	require.FileExists(t, env.stateBase()+".owner",
		"startup did not create its mountpoint-keyed lifetime ownership lock")
	require.FileExists(t, env.stateBase()+".lock",
		"startup did not create its mountpoint-keyed startup lock")
	devOld := env.mountIdentity(t)
	roDiffTree(t, env.sourceDir, env.mntDir, true)

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

	successor := env.spawnDaemonIncarnation(t, "new")
	env.requireServingSession(t, successor, 30*time.Second, 200*time.Millisecond,
		"the successor did not publish its control endpoint")
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

	roDiffTree(t, env.sourceDir, env.mntDir, true)
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
	_ = shutdownHeld.Close()
}

func TestFusePreReadyRollback(t *testing.T) {
	env, stressSource := setupContinuityHarness(t)

	old := env.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the daemon failed to mount")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"the daemon did not publish its control endpoint")
	devOld := env.mountIdentity(t)
	stress := startIOStress(env.mntDir, stressSource)

	fakeSuccessor := env.startFakeHotUpgradeSuccessor(t)

	// The old daemon is paused now; the kernel queues requests. Give the
	// stress loop time to pile a few up, then "crash" before reporting ready:
	// close our fd copy and the control connection (EOF).
	time.Sleep(2 * time.Second)
	require.NoError(t, fakeSuccessor.cmd.Process.Kill())
	require.True(t, fakeSuccessor.waitExit(controlProtocolTimeout))
	require.Error(t, fakeSuccessor.waitErr)

	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "resuming service")
	}, 15*time.Second, 200*time.Millisecond,
		"the old daemon did not resume after the successor died")
	require.True(t, old.alive(), "the old daemon must survive an aborted handoff")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"rollback did not restore the predecessor's control endpoint")
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

	successor := env.spawnDaemonIncarnation(t, "new")
	env.requireServingSession(t, successor, 30*time.Second, 200*time.Millisecond,
		"upgrade after rollback did not publish the successor's control endpoint")
	require.True(t, old.waitExit(30*time.Second), "the old daemon did not exit")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero: %v", old.cmd.ProcessState)
	roDiffTree(t, env.sourceDir, env.mntDir, true)

	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the successor ignored SIGTERM")
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
}

func TestFusePreReadyHelper(t *testing.T) {
	if os.Getenv("NYDUS_FUSE_PRE_READY_SUCCESSOR_HELPER") != "1" {
		t.Skip("helper process for TestFusePreReadyRollback")
	}

	mountpoint, err := filepath.EvalSymlinks(os.Getenv("NYDUS_FUSE_MOUNTPOINT"))
	require.NoError(t, err)
	imageBytes, err := os.ReadFile(os.Getenv("NYDUS_FUSE_BOOTSTRAP"))
	require.NoError(t, err)
	imageDigest := sha256.Sum256(imageBytes)
	conn, err := dialControl(strings.TrimPrefix(os.Getenv("NYDUS_FUSE_APISERVER"), "unix://"), 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	writeCtlFrame(t, conn, map[string]string{"type": "info"})
	info := readCtlFrame(t, conn)
	require.Equal(t, "info", info.Type)
	require.NotNil(t, info.Info)
	require.Equal(t, mountpoint, info.Info.Mountpoint)
	require.Equal(t, fmt.Sprintf("%x", imageDigest), info.Info.ImageDigest)
	require.Nil(t, info.SessionID)
	setControlDeadline(t, conn)
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
	var state ctlTransferState
	require.NoError(t, json.Unmarshal(metadata, &state))
	require.Equal(t, uint32(1), state.Version)
	require.Equal(t, mountpoint, state.Mountpoint)
	require.Equal(t, fmt.Sprintf("%x", imageDigest), state.ImageDigest)
	require.Equal(t, uint32(7), state.FuseSessionState.ProtoMajor)
	require.NotZero(t, state.FuseSessionState.ProtoMinor)
	fds, err := recvFDsExact(conn, 1)
	require.NoError(t, err)
	defer closeFDs(fds)
	var receivedFuse, fuseDevice unix.Stat_t
	require.NoError(t, unix.Fstat(fds[0], &receivedFuse))
	require.NoError(t, unix.Stat("/dev/fuse", &fuseDevice))
	require.Equal(t, uint32(unix.S_IFCHR), receivedFuse.Mode&unix.S_IFMT)
	require.Equal(t, fuseDevice.Rdev, receivedFuse.Rdev)

	_, err = fmt.Fprintln(os.Stdout, "TRANSFERRED")
	require.NoError(t, err)
	select {}
}

func TestFuseLiveOwnerWithoutControl(t *testing.T) {
	t.Run("missing", func(t *testing.T) { testFuseLiveOwnerWithoutControl(t, false) })
	t.Run("unresponsive", func(t *testing.T) { testFuseLiveOwnerWithoutControl(t, true) })
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
