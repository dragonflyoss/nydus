package nbd

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

const (
	heldFile       = "held.bin"
	heldFileSize   = 32 << 20
	stressFile     = "stress.bin"
	stressFileSize = 100 * 4096

	upgrades          = 4
	stressReaders     = 4
	saturatingReaders = 64

	startupLog       = "session startup complete"
	startupTimeout   = 45 * time.Second
	maxUpgradeStall  = 5 * time.Second
	maxFailoverStall = 45 * time.Second
)

type continuity struct {
	nydus      string
	workDir    string
	sourceDir  string
	blobDir    string
	bootstrap  string
	config     string
	mountpoint string
	apiSocket  string
	device     *device
}

func setup(t *testing.T, api bool) *continuity {
	t.Helper()
	NBD{}.Require(t)
	c := &continuity{
		nydus:   env.Nydus(t),
		workDir: env.WorkDir(t),
		device:  acquireDevice(t),
	}
	c.sourceDir = filepath.Join(c.workDir, "source")
	c.blobDir = filepath.Join(c.workDir, "blobs")
	c.bootstrap = filepath.Join(c.workDir, "bootstrap.boot")
	c.mountpoint = filepath.Join(c.workDir, "mnt")
	if !assert.NoError(t, os.MkdirAll(c.mountpoint, 0o755)) {
		t.FailNow()
	}

	mountpoint, err := filepath.EvalSymlinks(c.mountpoint)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	c.mountpoint = mountpoint
	if api {
		c.apiSocket = mount.SocketPath(t)
	}

	source := corpus.New(t, c.sourceDir)
	source.CreateRandomFile(t, heldFile, heldFileSize)
	source.CreateRandomFile(t, stressFile, stressFileSize)
	fixture.BuildInto(t, c.blobDir, c.bootstrap, c.sourceDir, fixture.MustLayout(t, "zstd-4k"))
	c.config = mount.LocalConfig(c.blobDir, filepath.Join(c.workDir, "cache")).Write(t, c.workDir, "config.json")

	t.Cleanup(func() {
		assert.NoError(t, os.RemoveAll(c.stateBase()+".lock"))
		assert.NoError(t, os.RemoveAll(c.stateBase()+".owner"))
	})

	t.Cleanup(func() { c.discardRetained(t) })

	return c
}

func (c *continuity) stateBase() string {
	digest := sha256.Sum256([]byte(c.device.path))
	return filepath.Join("/run/nydus/nbd", fmt.Sprint(os.Geteuid()), fmt.Sprintf("%x", digest))
}

func (c *continuity) spawn(t testing.TB, name string, extra ...string) *mount.Daemon {
	t.Helper()
	args := []string{
		"nbd",
		"--bootstrap", c.bootstrap,
		"--config", c.config,
		"--device", c.device.path,
		"--mountpoint", c.mountpoint,
		"--log-dir", mount.LogDir(c.workDir, name),
	}

	if c.apiSocket != "" {
		args = append(args, "--apiserver", "unix://"+c.apiSocket)
	}

	cmd := exec.Command(c.nydus, append(args, extra...)...)

	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NYDUS_NBD_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}

	return mount.StartCmd(t, c.workDir, name, cmd)
}

func (c *continuity) sectors(t testing.TB) uint64 {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.device.sysfs, "size"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	sectors, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return sectors
}

func (c *continuity) waitServing(t *testing.T, d *mount.Daemon) string {
	t.Helper()
	d.WaitForLog(t, startupTimeout, startupLog)

	if !assert.True(t, mount.IsMountpoint(c.mountpoint)) {
		t.FailNow()
	}

	data, err := os.ReadFile(c.stateBase() + ".owner")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var record struct {
		Version   int    `json:"version"`
		SessionID string `json:"session_id"`
		Options   struct {
			Connections int `json:"connections"`
			Timeout     int `json:"timeout_secs"`
		} `json:"options"`
	}
	if !assert.NoError(t, json.Unmarshal(data, &record)) {
		t.FailNow()
	}

	assert.Equal(t, 1, record.Version)
	assert.Equal(t, 2, record.Options.Connections)
	assert.Equal(t, 15, record.Options.Timeout)
	assert.NotEmpty(t, record.SessionID)

	timeout, err := os.ReadFile(filepath.Join(c.device.sysfs, "queue", "io_timeout"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, "15000", strings.TrimSpace(string(timeout)))
	assert.Eventually(t, func() bool { return workers(d) == 2 }, 10*time.Second, 50*time.Millisecond)

	return record.SessionID
}

func workers(d *mount.Daemon) int {
	names, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/comm", d.Pid()))
	if err != nil {
		return 0
	}

	count := 0

	for _, name := range names {
		if comm, err := os.ReadFile(name); err == nil && strings.HasPrefix(string(comm), "nydus_nbd_work") {
			count++
		}
	}

	return count
}

func (c *continuity) stop(t *testing.T, d *mount.Daemon) {
	t.Helper()
	d.Signal(unix.SIGTERM)

	if !assert.True(t, d.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Zero(t, d.ExitCode())
	assert.Eventually(t, func() bool {
		return !mount.IsMountpoint(c.mountpoint) && c.device.free()
	}, 10*time.Second, 100*time.Millisecond)
}

func (c *continuity) expectRejected(t *testing.T, d *mount.Daemon, reason string) {
	t.Helper()
	if !assert.True(t, d.WaitExit(15*time.Second)) {
		t.FailNow()
	}

	assert.Positive(t, d.ExitCode())
	assert.Contains(t, d.Log(), reason)
}

func (c *continuity) expectReleased(t *testing.T, d *mount.Daemon) {
	t.Helper()
	if !assert.True(t, d.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Zero(t, d.ExitCode())
	assert.Contains(t, d.Log(), "session released")
}

func (c *continuity) discardRetained(t *testing.T) {
	t.Helper()
	if c.device.free() {
		return
	}

	d := c.spawn(t, "cleanup")
	assert.Eventually(t, func() bool {
		return !d.Alive() || strings.Contains(d.Log(), startupLog)
	}, startupTimeout, 100*time.Millisecond)
	d.Stop()
	mount.Unmount(c.mountpoint)
}

type serving struct {
	initial *mount.Daemon
	session string
	sectors uint64
	dev     uint64
	mountID uint64
	held    *os.File
	mapped  []byte
	source  []byte
	stress  *ioStress
}

func mountIdentity(t *testing.T, path string) (dev, mountID uint64) {
	t.Helper()
	var stat unix.Statx_t
	if !assert.NoError(t, unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &stat)) {
		t.FailNow()
	}
	if !assert.NotZero(t, stat.Mask&unix.STATX_MNT_ID) {
		t.FailNow()
	}

	return unix.Mkdev(stat.Dev_major, stat.Dev_minor), stat.Mnt_id
}

func (c *continuity) startServing(t *testing.T, readers int) *serving {
	t.Helper()
	s := &serving{initial: c.spawn(t, "initial", "--threads", "2", "--timeout", "15")}
	s.session = c.waitServing(t, s.initial)
	s.sectors = c.sectors(t)
	s.dev, s.mountID = mountIdentity(t, c.mountpoint)

	var err error

	s.source, err = os.ReadFile(filepath.Join(c.sourceDir, heldFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	s.held, err = os.Open(filepath.Join(c.mountpoint, heldFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() {
		if s.held != nil {
			assert.NoError(t, s.held.Close())
		}
	})

	s.mapped, err = unix.Mmap(int(s.held.Fd()), 0, heldFileSize, unix.PROT_READ, unix.MAP_SHARED)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() {
		if s.mapped != nil {
			assert.NoError(t, unix.Munmap(s.mapped))
		}
	})

	first := make([]byte, heldFileSize/2)
	_, err = io.ReadFull(s.held, first)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(s.source[:len(first)], first)) {
		t.FailNow()
	}

	want, err := os.ReadFile(filepath.Join(c.sourceDir, stressFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	s.stress = c.startStress(t, want, s.sectors, readers)
	if !assert.Eventually(t, func() bool { return s.stress.count() > 0 }, 10*time.Second, 50*time.Millisecond) {
		t.FailNow()
	}

	return s
}

func (c *continuity) expectSameSession(t *testing.T, s *serving, d *mount.Daemon) {
	t.Helper()
	assert.Equal(t, s.session, c.waitServing(t, d))
	dev, mountID := mountIdentity(t, c.mountpoint)
	assert.Equal(t, s.dev, dev)
	assert.Equal(t, s.mountID, mountID)
	assert.Equal(t, s.sectors, c.sectors(t))
}

func (c *continuity) finish(t *testing.T, s *serving, current *mount.Daemon, maxStall time.Duration) {
	t.Helper()
	second, err := io.ReadAll(s.held)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.True(t, bytes.Equal(s.source[heldFileSize/2:], second))
	assert.NoError(t, unix.Fadvise(int(s.held.Fd()), 0, 0, unix.FADV_DONTNEED))
	assert.NoError(t, unix.Madvise(s.mapped, unix.MADV_DONTNEED))
	assert.True(t, bytes.Equal(s.source, s.mapped))
	assert.NoError(t, unix.Munmap(s.mapped))
	s.mapped = nil
	assert.NoError(t, s.held.Close())
	s.held = nil

	ops, errs, stall := s.stress.stop()
	assert.Positive(t, ops)
	assert.Empty(t, errs)
	assert.Less(t, stall, maxStall)
	t.Logf("NBD continuity: %d cache-evicting reads, max stall %v", ops, stall)
	c.stop(t, current)
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

func (c *continuity) startStress(t *testing.T, want []byte, sectors uint64, readers int) *ioStress {
	t.Helper()
	s := &ioStress{stopCh: make(chan struct{}), doneCh: make(chan struct{})}

	t.Cleanup(func() { s.stopOnce.Do(func() { close(s.stopCh) }) })

	path := filepath.Join(c.mountpoint, stressFile)
	size := filepath.Join(c.device.sysfs, "size")
	var running sync.WaitGroup

	for range readers {
		running.Add(1)

		go func() {
			defer running.Done()

			for {
				select {
				case <-s.stopCh:
					return

				default:
				}

				start := time.Now()
				var errs []string

				if err := readEvicting(path, want); err != nil {
					errs = append(errs, err.Error())
				}

				data, err := os.ReadFile(size)
				if err != nil || strings.TrimSpace(string(data)) != strconv.FormatUint(sectors, 10) {
					errs = append(errs, fmt.Sprintf("capacity changed: %q (%v)", data, err))
				}

				s.mu.Lock()
				s.ops++
				s.errs = append(s.errs, errs...)
				s.maxStall = max(s.maxStall, time.Since(start))
				s.mu.Unlock()
			}
		}()
	}

	go func() {
		running.Wait()
		close(s.doneCh)
	}()

	return s
}

func readEvicting(path string, want []byte) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	got, err := io.ReadAll(file)
	if err == nil && !bytes.Equal(want, got) {
		err = errors.New("content mismatch")
	}

	return errors.Join(err, unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_DONTNEED), file.Close())
}

func (s *ioStress) count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ops
}

func (s *ioStress) stop() (int64, []string, time.Duration) {
	s.stopOnce.Do(func() { close(s.stopCh) })
	<-s.doneCh
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ops, s.errs, s.maxStall
}

func TestHotUpgrade(t *testing.T) {
	t.Parallel()
	c := setup(t, true)
	s := c.startServing(t, stressReaders)

	wrongMount := *c
	wrongMount.mountpoint = filepath.Join(c.workDir, "other-mnt")
	if !assert.NoError(t, os.Mkdir(wrongMount.mountpoint, 0o755)) {
		t.FailNow()
	}

	c.expectRejected(t, wrongMount.spawn(t, "wrong-mount"), "mismatch")

	wrongImage := *c
	wrongImage.bootstrap = filepath.Join(c.workDir, "other.boot")
	other := corpus.New(t, filepath.Join(c.workDir, "other-source"))
	other.CreateRandomFile(t, "file", 4096)
	fixture.BuildInto(t, c.blobDir, wrongImage.bootstrap, other.Dir, fixture.MustLayout(t, "zstd-4k"))
	c.expectRejected(t, wrongImage.spawn(t, "wrong-image"), "mismatch")

	if !assert.True(t, s.initial.Alive()) {
		t.FailNow()
	}

	bootstrap, err := os.ReadFile(c.bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	c.bootstrap = filepath.Join(c.workDir, "same-content.boot")
	if !assert.NoError(t, os.WriteFile(c.bootstrap, bootstrap, 0o644)) {
		t.FailNow()
	}

	current := s.initial

	for generation := 1; generation <= upgrades; generation++ {
		next := c.spawn(t, fmt.Sprintf("upgrade-%d", generation), "--threads", "1", "--timeout", "60")
		c.expectSameSession(t, s, next)
		c.expectReleased(t, current)

		current = next
	}

	c.finish(t, s, current, maxUpgradeStall)
}

func TestHotUpgradeUnderLoad(t *testing.T) {
	t.Parallel()
	c := setup(t, true)
	s := c.startServing(t, saturatingReaders)
	next := c.spawn(t, "saturated-upgrade", "--threads", "1")
	c.expectSameSession(t, s, next)
	c.expectReleased(t, s.initial)
	c.finish(t, s, next, maxUpgradeStall)
}

func TestFailover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		api  bool
	}{
		{name: "with api", api: true},
		{name: "without api", api: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { failover(t, tc.api) })
	}
}

func failover(t *testing.T, api bool) {
	c := setup(t, api)
	s := c.startServing(t, stressReaders)
	if !api {
		c.expectRejected(t, c.spawn(t, "live-owner", "--threads", "1"), "session ownership")

		if !assert.True(t, s.initial.Alive()) {
			t.FailNow()
		}
	}

	current := s.initial

	for crash := 1; crash <= 2; crash++ {
		current.Kill()

		if crash == 1 {
			c.expectInvalidRecordRejected(t, s)
		}

		current = c.spawn(t, fmt.Sprintf("recovery-%d", crash), "--threads", "1", "--timeout", "60")
		if crash == 2 && api {
			current = soleOwner(t, current, c.spawn(t, "concurrent-recovery", "--threads", "3"))
		}

		c.expectSameSession(t, s, current)
	}

	c.finish(t, s, current, maxFailoverStall)
}

func TestRestartAfterBusyShutdown(t *testing.T) {
	t.Parallel()
	c := setup(t, false)
	args := []string{"--threads", "2", "--timeout", "15"}
	initial := c.spawn(t, "initial", args...)
	session := c.waitServing(t, initial)
	sectors := c.sectors(t)

	held, err := os.Open(filepath.Join(c.mountpoint, heldFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	t.Cleanup(func() { _ = held.Close() })

	initial.Signal(unix.SIGTERM)

	if !assert.True(t, initial.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Positive(t, initial.ExitCode())
	assert.Contains(t, initial.Log(), "kept the NBD session")
	if !assert.True(t, mount.IsMountpoint(c.mountpoint)) || !assert.Equal(t, sectors, c.sectors(t)) {
		t.FailNow()
	}

	recovered := c.spawn(t, "recovered", args...)
	assert.Equal(t, session, c.waitServing(t, recovered))

	source, err := os.ReadFile(filepath.Join(c.sourceDir, heldFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	tail := make([]byte, 1<<20)
	_, err = held.ReadAt(tail, heldFileSize-int64(len(tail)))
	assert.NoError(t, err)
	assert.Equal(t, source[heldFileSize-len(tail):], tail)
	assert.NoError(t, held.Close())

	c.stop(t, recovered)
}

func (c *continuity) expectInvalidRecordRejected(t *testing.T, s *serving) {
	t.Helper()
	owner := c.stateBase() + ".owner"
	record, err := os.ReadFile(owner)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(owner, []byte(`{"invalid":true}`), 0o600)) {
		t.FailNow()
	}

	rejected := c.spawn(t, "invalid-record", "--threads", "1")
	exited := rejected.WaitExit(15 * time.Second)
	if !assert.NoError(t, os.WriteFile(owner, record, 0o600)) {
		t.FailNow()
	}
	if !assert.True(t, exited) {
		t.FailNow()
	}

	assert.Positive(t, rejected.ExitCode())
	assert.Equal(t, s.sectors, c.sectors(t))
}

func soleOwner(t *testing.T, a, b *mount.Daemon) *mount.Daemon {
	t.Helper()
	var owner *mount.Daemon
	if !assert.Eventually(t, func() bool {
		for _, pair := range [][2]*mount.Daemon{{a, b}, {b, a}} {
			if pair[0].Alive() && !pair[1].Alive() && strings.Contains(pair[0].Log(), startupLog) {
				owner = pair[0]
				return true
			}
		}

		return false
	}, startupTimeout, 100*time.Millisecond) {
		t.FailNow()
	}

	return owner
}
