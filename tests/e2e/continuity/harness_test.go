package continuity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
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

	maxUpgradeStall        = 20 * time.Second
	controlProtocolTimeout = 10 * time.Second

	// helperInheritedFD is the first descriptor a helper process inherits
	// through exec.Cmd.ExtraFiles.
	helperInheritedFD = 3
)

type harness struct {
	nydus            string
	workDir          string
	sourceDir        string
	blobDir          string
	mountpoint       string
	bootstrap        string
	controlSocket    string
	supervisorSocket string

	holder *fakeRecoveryHolder
}

func (h *harness) spawn(t testing.TB, name string, extra ...string) *mount.Daemon {
	t.Helper()
	args := []string{
		"fuse",
		"--bootstrap", h.bootstrap,
		"--blob-dir", h.blobDir,
		"--mountpoint", h.mountpoint,
		"--log-dir", mount.LogDir(h.workDir, name),
	}

	if h.controlSocket != "" {
		args = append(args, "--apiserver", "unix://"+h.controlSocket)
	}

	if h.supervisorSocket != "" {
		args = append(args, "--supervisor-socket", "unix://"+h.supervisorSocket)
	}

	args = append(args, extra...)
	cmd := exec.Command(h.nydus, args...)

	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NYDUS_FUSE_APISERVER=") &&
			!strings.HasPrefix(entry, "NYDUS_FUSE_SUPERVISOR_SOCKET=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}

	return mount.StartCmd(t, h.workDir, name, cmd)
}

func mountDev(t testing.TB, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if !assert.NoError(t, unix.Stat(path, &st)) {
		t.FailNow()
	}

	return st.Dev
}

func (h *harness) waitMounted(t *testing.T) {
	t.Helper()
	if !assert.Eventually(t, func() bool { return mount.IsMountpoint(h.mountpoint) },
		20*time.Second, 200*time.Millisecond) {
		t.FailNow()
	}
}

func (h *harness) waitUnmounted(t *testing.T) {
	t.Helper()
	if !assert.Eventually(t, func() bool { return !mount.IsMountpoint(h.mountpoint) },
		10*time.Second, 200*time.Millisecond) {
		t.FailNow()
	}
}

// waitServing waits until daemon answers on the control endpoint with the
// expected Session Identity; a nil sessionID expects a standalone session.
func (h *harness) waitServing(t *testing.T, daemon *mount.Daemon, sessionID *string, timeout time.Duration) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		info, err := requestControlInfo(h.controlSocket)
		if err != nil || info.Info.PID != uint32(daemon.Pid()) {
			return false
		}
		if sessionID == nil {
			return info.SessionID == nil
		}

		return info.SessionID != nil && *info.SessionID == *sessionID
	}, timeout, 100*time.Millisecond) {
		t.FailNow()
	}
}

func (h *harness) waitControlOwner(t *testing.T, daemon *mount.Daemon, timeout time.Duration) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		pid, err := controlOwnerPID(h.controlSocket)
		return err == nil && pid == uint32(daemon.Pid())
	}, timeout, 100*time.Millisecond) {
		t.FailNow()
	}
}

func (h *harness) waitControlUnavailable(t *testing.T) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		_, err := requestControlInfo(h.controlSocket)
		return err != nil
	}, 10*time.Second, 100*time.Millisecond) {
		t.FailNow()
	}
}

func (h *harness) expectMountIdentity(t *testing.T, want uint64) {
	t.Helper()
	assert.Equal(t, want, mountDev(t, h.mountpoint))
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.nydus = env.Nydus(t)
	h.workDir = env.WorkDir(t)
	h.sourceDir = filepath.Join(h.workDir, "source")
	h.blobDir = filepath.Join(h.workDir, "blobs")
	h.mountpoint = filepath.Join(h.workDir, "mnt")
	h.bootstrap = filepath.Join(h.workDir, "bootstrap.boot")

	h.controlSocket = mount.SocketPath(t)
	if !assert.NoError(t, os.MkdirAll(h.sourceDir, 0o755)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.MkdirAll(h.mountpoint, 0o755)) {
		t.FailNow()
	}

	mntDir, err := filepath.EvalSymlinks(h.mountpoint)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	h.mountpoint = mntDir

	t.Cleanup(func() {
		_ = os.Remove(h.stateBase() + ".lock")
		_ = os.Remove(h.stateBase() + ".owner")
	})

	t.Cleanup(func() { mount.Unmount(h.mountpoint) })

	return h
}

func (h *harness) stateBase() string {
	digest := sha256.Sum256([]byte(h.mountpoint))
	return filepath.Join("/run/nydus/fuse", fmt.Sprint(os.Geteuid()), fmt.Sprintf("%x", digest))
}

// setup builds the continuity image. A protected harness also runs a fake
// Recovery Holder that every daemon it spawns is pointed at.
func setup(t *testing.T, protected bool) (*harness, []byte) {
	t.Helper()
	mount.FUSE{}.Require(t)
	h := newHarness(t)
	stressSource := bytes.Repeat([]byte("nydus-failover\n"), stressFileSize/15+1)
	stressSource = stressSource[:stressFileSize]
	stressPath := filepath.Join(h.sourceDir, stressFileRel)
	if !assert.NoError(t, os.MkdirAll(filepath.Dir(stressPath), 0o755)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(stressPath, stressSource, 0o644)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(
		filepath.Join(h.sourceDir, recoveryHeldFileRel),
		stressSource,
		0o644,
	)) {
		t.FailNow()
	}

	heldSource := bytes.Repeat([]byte("nydus-hot-upgrade\n"), heldFileSize/18+1)
	if !assert.NoError(t, os.WriteFile(
		filepath.Join(h.sourceDir, heldFileRel),
		heldSource[:heldFileSize],
		0o644,
	)) {
		t.FailNow()
	}

	dirPath := filepath.Join(h.sourceDir, heldDirRel)
	if !assert.NoError(t, os.MkdirAll(dirPath, 0o755)) {
		t.FailNow()
	}

	for i := range heldDirEntries {
		assert.NoError(t, os.WriteFile(
			filepath.Join(dirPath, fmt.Sprintf("entry_%04d", i)),
			[]byte{byte(i)},
			0o644,
		))
	}

	if !assert.NoError(t, unix.Setxattr(
		filepath.Join(h.sourceDir, heldFileRel),
		heldFileXattrName,
		[]byte(heldFileXattrValue),
		0,
	)) {
		t.FailNow()
	}

	layout := fixture.MustLayout(t, "zstd-4k")
	fixture.BuildInto(t, h.blobDir, h.bootstrap, h.sourceDir, layout)

	if protected {
		h.supervisorSocket = filepath.Join(filepath.Dir(h.controlSocket), "supervisor.sock")
		newFakeRecoveryHolder(t, h)
	}

	return h, stressSource
}

type ioStress struct {
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	ops      int64
	errs     []string
	maxStall time.Duration

	crashGeneration int64
	eioByCrash      map[int64]int64
}

func (h *harness) startStress(t *testing.T, want []byte) *ioStress {
	t.Helper()
	mntDir := h.mountpoint

	s := &ioStress{
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		eioByCrash: make(map[int64]int64),
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

			// An operation that spans a crash may fail once with EIO or
			// ECONNABORTED; those are counted per crash, not reported.
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
			got, err := os.ReadFile(filePath)
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
			entries, err := os.ReadDir(dirPath)
			if err != nil {
				recordError("readdir "+heldDirRel, err, readdirGeneration)
			} else if len(entries) != heldDirEntries {
				errs = append(errs, fmt.Sprintf("readdir %s: %d entries, want %d",
					heldDirRel, len(entries), heldDirEntries))
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

func (s *ioStress) count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ops
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

func (h *harness) openPartialDir(t *testing.T, rel string) *partialDirReader {
	t.Helper()
	return openPartialDirAt(t, filepath.Join(h.mountpoint, rel))
}

func openPartialDirAt(t *testing.T, path string) *partialDirReader {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

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
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if n == 0 {
		return true
	}

	_, _, r.names = unix.ParseDirent(buf[:n], -1, r.names)

	return false
}

func (r *partialDirReader) readRest(t *testing.T) {
	t.Helper()
	for _, e := range fstest.DrainDirents(t, r.fd, 512) {
		r.names = append(r.names, e.Name)
	}
}

func (r *partialDirReader) close() {
	_ = unix.Close(r.fd)
	r.fd = -1
}

func (h *harness) startFakeHotUpgradeSuccessor(t *testing.T, sessionID *string) *mount.Daemon {
	t.Helper()
	sessionJSON, err := json.Marshal(sessionID)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestPreReadyRollback$")

	cmd.Env = append(os.Environ(),
		preReadyHelperEnv+"=1",
		"NYDUS_E2E_FUSE_APISERVER=unix://"+h.controlSocket,
		"NYDUS_E2E_FUSE_MOUNTPOINT="+h.mountpoint,
		"NYDUS_E2E_FUSE_BOOTSTRAP="+h.bootstrap,
		preReadySessionEnv+"="+string(sessionJSON),
	)

	stdout, w, err := os.Pipe()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = stdout.Close() })

	cmd.Stdout = w
	successor := mount.StartCmd(t, t.TempDir(), "pre-ready-successor", cmd)
	_ = w.Close()
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
		assert.NoError(t, err)

	case <-time.After(10 * time.Second):
		t.Fatalf("pre-READY successor did not receive the Session Transfer: %s", successor.Log())
	}

	return successor
}

func (h *harness) requireFilesystem(
	t *testing.T,
	want []byte,
	wantDev uint64,
) {
	t.Helper()
	h.expectMountIdentity(t, wantDev)
	got, err := os.ReadFile(filepath.Join(h.mountpoint, stressFileRel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, want, got) {
		t.FailNow()
	}

	var stat unix.Stat_t
	if !assert.NoError(t, unix.Stat(filepath.Join(h.mountpoint, stressFileRel), &stat)) {
		t.FailNow()
	}

	assert.Equal(t, int64(len(want)), stat.Size)
	entries, err := os.ReadDir(filepath.Join(h.mountpoint, heldDirRel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Len(t, entries, heldDirEntries)
}
