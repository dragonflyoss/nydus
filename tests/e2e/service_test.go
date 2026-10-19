package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// serviceSuite is the environment the nbd and fanotify suites share: the
// source tree and its hashes, the image, the chunk cache, the daemon with its
// logs and the cases proving that on-demand reads through either kernel path
// are byte-exact and range-bounded, that the warm cache short-circuits the
// fetch across a restart and that SIGTERM shuts the daemon down cleanly. A
// suite embeds it and fills in the daemon's command line, its readiness and
// shutdown log lines and what to wait for after a stop.
type serviceSuite struct {
	// Daemon is the running service daemon with its logs.
	util.Daemon

	// args is the daemon's command line.
	args []string

	// afterStop waits for what the kernel releases once the daemon exited,
	// nbd's device; nil when there is nothing to wait for.
	afterStop func(t *testing.T)

	// readyPattern matches the log line the daemon writes once it serves the
	// mount.
	readyPattern string

	// shutdownPattern matches the log line of the daemon's shutdown path.
	shutdownPattern string

	// workDir is the temporary root every other path lives under.
	workDir string

	// source holds the tree the image is built from.
	source string

	// blobDir holds the blobs the build writes.
	blobDir string

	// cacheDir is the daemon's chunk cache.
	cacheDir string

	// mountpoint is the daemon's mountpoint.
	mountpoint string

	// configPath is the daemon's backend config.
	configPath string

	// bootstrap is the bootstrap the daemon mounts.
	bootstrap string

	// sourceHashes is the sha256 of every source file, keyed by relative path.
	sourceHashes map[string]string
}

// newServiceSuite lays the paths out under a temporary directory, writes and
// hashes the source tree and registers the cleanup that stops the daemon and
// unmounts what it left behind.
func newServiceSuite(t *testing.T) *serviceSuite {
	t.Helper()
	workDir := t.TempDir()
	s := &serviceSuite{
		Daemon: util.Daemon{
			ConsoleLog: filepath.Join(workDir, "daemon.console.log"),
			LogDir:     filepath.Join(workDir, "logs"),
		},
		workDir:    workDir,
		source:     filepath.Join(workDir, "source"),
		blobDir:    filepath.Join(workDir, "blobs"),
		cacheDir:   filepath.Join(workDir, "cache"),
		mountpoint: filepath.Join(workDir, "mnt"),
		configPath: filepath.Join(workDir, "config.yaml"),
		bootstrap:  filepath.Join(workDir, "bootstrap.boot"),
	}

	// A reader denied mid-fault can keep the mount busy; Unmount never hangs.
	t.Cleanup(func() {
		s.Stop()
		util.Unmount(s.mountpoint)
	})
	s.writeSource(t)

	return s
}

// writeSource writes the source tree the image is built from and hashes it.
func (s *serviceSuite) writeSource(t *testing.T) {
	t.Helper()
	for _, dir := range []string{
		filepath.Join(s.source, "subdir"),
		filepath.Join(s.source, "many"),
		s.blobDir, s.cacheDir, s.mountpoint, s.LogDir,
	} {
		assert.NoError(t, os.MkdirAll(dir, 0o755))
	}

	// A tiny file, a ~400K file, a 64M file, a nested file and a fan of 48
	// small files of deterministic sizes for the concurrency case.
	assert.NoError(t, os.WriteFile(filepath.Join(s.source, "hello.txt"), []byte("hello nydus\n"), 0o644))
	util.WriteRandomFile(t, filepath.Join(s.source, "data.bin"), 100*4096)
	util.WriteRandomFile(t, filepath.Join(s.source, "large.bin"), 64*1024*1024)
	assert.NoError(t, os.WriteFile(filepath.Join(s.source, "subdir", "nested.txt"), []byte("nested file content\n"), 0o644))
	for i := 1; i <= 48; i++ {
		size := (4 + (i*7)%20) * 4096
		util.WriteRandomFile(t, filepath.Join(s.source, "many", fmt.Sprintf("f%d.bin", i)), size)
	}

	s.sourceHashes = util.Sha256Tree(t, s.source)
}

// start launches the daemon on whatever the cache holds and waits for it to
// serve the mount. Warm-cache restarts use it directly.
func (s *serviceSuite) start(t *testing.T) {
	t.Helper()
	s.startArgs(t, s.args...)
}

// startArgs launches the command line args, the daemon's own or one wrapping
// it in a tracer, and waits for the mount and the readiness log line.
func (s *serviceSuite) startArgs(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	s.Start(t, cmd)

	// The mount and the readiness line arrive in either order, so wait for
	// both.
	s.WaitReady(t, func() bool {
		return util.IsMountpoint(s.mountpoint) && s.CountLogs(s.readyPattern) > 0
	})
	t.Logf("daemon ready (pid=%d)", cmd.Process.Pid)
}

// startCold wipes the cache and starts the daemon on it.
func (s *serviceSuite) startCold(t *testing.T) {
	t.Helper()
	util.WipeCache(s.cacheDir)
	s.start(t)
}

// restartCold stops the daemon and starts it again on an empty cache.
func (s *serviceSuite) restartCold(t *testing.T) {
	t.Helper()
	s.stop(t)
	s.startCold(t)
}

// stop stops the daemon, waits for what the kernel has to release and reports
// whether the daemon exited on its own.
func (s *serviceSuite) stop(t *testing.T) bool {
	t.Helper()
	exited := s.Stop()
	if s.afterStop != nil {
		s.afterStop(t)
	}

	return exited
}

// run runs the cases in order: readiness, the suite's own first case, then
// the shared ones with health, the suite's log check, after the whole tree
// was read. Order matters, since several cases restart the daemon and depend
// on state left by earlier ones. Subtests keep going on soft-assert failures,
// so a broken case does not mask the rest.
func (s *serviceSuite) run(t *testing.T, readiness, health func(t *testing.T)) {
	t.Run("readiness", readiness)
	t.Run("metadata off path", s.caseMetadataOffpath)
	t.Run("tiny file", s.caseTinyFile)
	t.Run("partial range bounded", s.casePartialRangeBounded)
	t.Run("full integrity", s.caseFullIntegrity)
	t.Run("daemon health", health)
	t.Run("warm fast path", s.caseWarmFastpath)
	t.Run("concurrency", s.caseConcurrency)
	t.Run("persistence", s.casePersistence)
	t.Run("graceful shutdown", s.caseGracefulShutdown)
}

// caseMetadataOffpath checks ls and stat are served off the local bootstrap
// and do not balloon the blob cache.
func (s *serviceSuite) caseMetadataOffpath(t *testing.T) {
	assert := assert.New(t)
	before := s.cacheAllocatedBytes(t)

	assert.NoError(exec.Command("ls", "-la", s.mountpoint).Run(), "ls mountpoint failed")
	_, err := os.Stat(filepath.Join(s.mountpoint, "large.bin"))
	assert.NoError(err, "stat large.bin failed")
	assert.NoError(exec.Command("ls", "-la", filepath.Join(s.mountpoint, "subdir")).Run(), "ls subdir failed")

	after := s.cacheAllocatedBytes(t)
	assert.Less(after-before, int64(1<<20), "ls and stat filled the blob cache")
}

// caseTinyFile checks a single-block file is byte-exact.
func (s *serviceSuite) caseTinyFile(t *testing.T) {
	assert := assert.New(t)
	got := util.Sha256File(t, filepath.Join(s.mountpoint, "hello.txt"))
	want := util.Sha256File(t, filepath.Join(s.source, "hello.txt"))
	assert.Equal(want, got, "hello.txt differs from the source")

	content, err := os.ReadFile(filepath.Join(s.mountpoint, "hello.txt"))
	assert.NoError(err)
	assert.Equal("hello nydus\n", string(content), "hello.txt content differs")
}

// casePartialRangeBounded is the decisive demand-paging case: mid-file 1MiB
// slices are byte-exact and pull bounded ranges, not the whole blob.
func (s *serviceSuite) casePartialRangeBounded(t *testing.T) {
	assert := assert.New(t)

	// Fresh cache so the measurement is clean: mid-file 1MiB slices only.
	s.restartCold(t)
	before := s.cacheAllocatedBytes(t)
	mountedLarge := filepath.Join(s.mountpoint, "large.bin")
	sourceLarge := filepath.Join(s.source, "large.bin")
	for _, skip := range []int64{1, 17, 40, 63} {
		got := util.Sha256Range(t, mountedLarge, skip<<20, 1<<20)
		want := util.Sha256Range(t, sourceLarge, skip<<20, 1<<20)
		assert.Equal(want, got, "large.bin[+%dMiB,1MiB] differs from the source", skip)
	}

	// 4 * 1MiB of logical reads; the fetch size may amplify, but pulling the
	// whole 64MiB blob per slice would blow way past this.
	after := s.cacheAllocatedBytes(t)
	assert.Less(after-before, int64(24*1024*1024), "partial reads pulled more than bounded ranges")
	assert.Less(after, int64(48*1024*1024), "cache approaches the full blob after partial reads")
}

// caseFullIntegrity checks every file hashes like its source and that
// reading the tree fills the cache.
func (s *serviceSuite) caseFullIntegrity(t *testing.T) {
	assert := assert.New(t)
	before := s.cacheAllocatedBytes(t)
	mountHashes := util.Sha256Tree(t, s.mountpoint)
	after := s.cacheAllocatedBytes(t)

	assert.Equal(s.sourceHashes, mountHashes, "full-tree sha256 differs from the source")
	assert.Greater(after, before, "reading the tree did not grow the blob cache")
	assert.Greater(after, int64(40*1024*1024), "cache is not near-full after reading all data")
}

// caseWarmFastpath checks that, with everything cached by the full read, a
// warm re-read serves identical bytes and allocates no new blocks because
// the fully-ready fast path short-circuits the fetch.
func (s *serviceSuite) caseWarmFastpath(t *testing.T) {
	assert := assert.New(t)
	before := s.cacheAllocatedBytes(t)
	got := util.Sha256File(t, filepath.Join(s.mountpoint, "large.bin"))
	want := util.Sha256File(t, filepath.Join(s.source, "large.bin"))
	after := s.cacheAllocatedBytes(t)

	assert.Equal(want, got, "warm re-read differs from the source")
	assert.Less(after-before, int64(1<<20), "warm re-read allocated new cache blocks")
}

// caseConcurrency stresses the daemon with many parallel readers: all
// return, all are correct, no fetch worker panics and the daemon survives.
func (s *serviceSuite) caseConcurrency(t *testing.T) {
	assert := assert.New(t)
	s.restartCold(t)

	// Read the fan of small files whole and overlapping 2MiB slices of the
	// large file at the same time. A dead mount lists no files, so the fan
	// must be complete before the fan-out.
	var wg sync.WaitGroup
	var failed atomic.Bool
	manyFiles, _ := filepath.Glob(filepath.Join(s.mountpoint, "many", "*.bin"))
	assert.Len(manyFiles, 48, "the fan of small files is incomplete")
	for _, path := range manyFiles {
		wg.Go(func() {
			if _, err := os.ReadFile(path); err != nil {
				failed.Store(true)
			}
		})
	}
	mountedLarge := filepath.Join(s.mountpoint, "large.bin")
	for _, skip := range []int64{0, 4, 8, 8, 12, 16, 16, 20} {
		wg.Go(func() {
			if _, err := util.ReadRange(mountedLarge, skip<<20, 2<<20); err != nil {
				failed.Store(true)
			}
		})
	}
	wg.Wait()
	assert.False(failed.Load(), "a concurrent reader failed")

	// Verify the fan of small files against the source.
	mismatched := 0
	sourceMany, _ := filepath.Glob(filepath.Join(s.source, "many", "*.bin"))
	for _, f := range sourceMany {
		if util.Sha256File(t, filepath.Join(s.mountpoint, "many", filepath.Base(f))) != util.Sha256File(t, f) {
			mismatched++
		}
	}
	assert.Equal(0, mismatched, "concurrently read small files differ from the source")
	assert.Equal(0, s.CountLogs(`fetch worker panicked`), "a fetch worker panicked")
	assert.True(s.Alive(), "daemon died under stress")
}

// casePersistence checks a warm cache survives a daemon restart and serves
// without new cache allocation.
func (s *serviceSuite) casePersistence(t *testing.T) {
	assert := assert.New(t)

	// Warm the whole tree, then restart without clearing the cache dir.
	_ = util.ReadWhole(t, filepath.Join(s.mountpoint, "large.bin"))
	_ = util.ReadWhole(t, filepath.Join(s.mountpoint, "data.bin"))
	manyFiles, _ := filepath.Glob(filepath.Join(s.mountpoint, "many", "*.bin"))
	for _, f := range manyFiles {
		_ = util.ReadWhole(t, f)
	}

	before := s.cacheAllocatedBytes(t)
	s.stop(t)
	t.Log("restarting daemon with warm cache (no wipe)")
	s.start(t)

	// The core's persisted chunk map short-circuits the fetch, so re-reading
	// the same data must not grow the cache.
	got := util.Sha256File(t, filepath.Join(s.mountpoint, "large.bin"))
	want := util.Sha256File(t, filepath.Join(s.source, "large.bin"))
	assert.Equal(want, got, "large.bin differs from the source after restart")
	after := s.cacheAllocatedBytes(t)
	assert.Less(after-before, int64(1<<20), "warm cache allocated new blocks after restart")
}

// caseGracefulShutdown checks SIGTERM makes the daemon exit on its own, log
// the shutdown and leave no mount behind.
func (s *serviceSuite) caseGracefulShutdown(t *testing.T) {
	assert := assert.New(t)
	assert.True(s.Alive(), "daemon is not running")
	assert.True(s.stop(t), "daemon did not exit on SIGTERM")
	assert.Greater(s.CountLogs(s.shutdownPattern), 0, "shutdown path not logged")
	assert.Eventually(func() bool { return !util.IsMountpoint(s.mountpoint) },
		10*time.Second, 100*time.Millisecond, "mountpoint leaked after shutdown")
}

// blobDataFiles returns every *.blob.data file in the cache dir.
func (s *serviceSuite) blobDataFiles() []string {
	matches, _ := filepath.Glob(filepath.Join(s.cacheDir, "*.blob.data"))
	return matches
}

// cacheAllocatedBytes sums the allocated bytes of every *.blob.data file, the
// demand-paging signal: a hole file reports close to zero until a chunk is
// fetched.
func (s *serviceSuite) cacheAllocatedBytes(t *testing.T) int64 {
	t.Helper()
	var total int64
	for _, blobData := range s.blobDataFiles() {
		total += util.AllocatedBytes(t, blobData)
	}

	return total
}
