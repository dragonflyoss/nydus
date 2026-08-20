package e2e

// NBD END-TO-END test (local backend, no docker/registry).
//
// Boots the real `nydus nbd` daemon against a LOCAL backend (an on-disk blob
// directory produced by `nydus build --blob-dir`, no OCI registry, no docker),
// attaches a free /dev/nbdX, mounts it as EROFS on demand, and asserts — with
// byte-exact hashes, cache-growth measurements and daemon logs — that cold
// reads through the NBD socket are correct and demand-paged.
//
// This mirrors the fanotify E2E suite (cases C0-C10) but routes guest reads
// through the NBD socket protocol instead of fanotify pre-content hooks, so
// it works on any kernel with the nbd driver (no 6.15 FAN_PRE_ACCESS
// requirement). The cache fill philosophy is identical: idempotent in-place
// cache writes, sticky fully-ready bypass.
//
// Cases:
//
//	C0  service readiness + cache starts empty/sparse (bootstrap serves metadata)
//	C1  metadata (ls/stat) served off the local bootstrap, not blob cache
//	C2  tiny single-block file: byte-exact content
//	C3  mid-file PARTIAL read is byte-exact AND range-bounded (not whole-blob)
//	C4  full-tree integrity: every file's sha256 == source
//	C5  demand-paging proof: cache grows empty -> filled, correlated to reads
//	C6  daemon health: no bad-magic / short-read / backend-failure errors
//	C7  warm fast-path: re-read is byte-exact, ~no new cache allocation
//	C8  concurrency/stress: many parallel readers, all correct, no deadlock
//	C9  persistence across restart: warm cache re-serves with no new fetch
//	C10 graceful shutdown: SIGTERM -> clean unmount, no leak
//
// HARD REQUIREMENTS (the test skips loudly if unmet):
//   - root (NBD ioctls + mount need CAP_SYS_ADMIN)
//   - Linux with the nbd kernel module (modprobe nbd or built-in)
//   - erofs kernel support (check /proc/filesystems)
//   - nydus binary with the nbd subcommand (build with --features cli,nbd)
//
// Environment overrides:
//
//	NYDUS_BIN    path to the nydus binary (default: in-tree lookup)
//	NBD_DEVICE   path to a specific /dev/nbdX (default: auto-find a free one)

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var nbdReadFailurePattern = regexp.MustCompile(`nbd: read .* failed:`)

// nbdEnv holds the paths, binaries and process handles for one E2E run.
type nbdEnv struct {
	daemonProc

	nydusBin string
	device   string

	workDir    string
	sourceDir  string
	blobDir    string
	cacheDir   string
	mntDir     string
	configPath string
	bootstrap  string

	sourceHashes map[string]string // rel path -> sha256
}

func TestNbd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("NBD E2E requires Linux")
	}
	if os.Getuid() != 0 {
		t.Skip("NBD E2E requires root (CAP_SYS_ADMIN for ioctls + mount)")
	}
	if !erofsSupported() {
		t.Skip("erofs not in /proc/filesystems — kernel lacks EROFS support")
	}

	device, err := findFreeNbdDevice()
	if err != nil {
		t.Skipf("no free NBD device: %v (is the nbd module loaded? try: modprobe nbd)", err)
	}

	env := &nbdEnv{device: device}
	env.nydusBin = lookupBinFromEnv(t, "NYDUS_BIN", "nydus")
	if out, err := exec.Command(env.nydusBin, "nbd", "--help").CombinedOutput(); err != nil {
		t.Skipf("nydus binary lacks the nbd subcommand; build with --features cli,nbd: %s", out)
	}

	env.workDir = t.TempDir()
	env.sourceDir = filepath.Join(env.workDir, "source")
	env.blobDir = filepath.Join(env.workDir, "blobs")
	env.cacheDir = filepath.Join(env.workDir, "cache")
	env.mntDir = filepath.Join(env.workDir, "mnt")
	env.logDir = filepath.Join(env.workDir, "logs")
	env.configPath = filepath.Join(env.workDir, "config.yaml")
	env.daemonLog = filepath.Join(env.workDir, "daemon.console.log")
	env.bootstrap = filepath.Join(env.workDir, "bootstrap.boot")

	t.Cleanup(func() { env.cleanup(t) })

	env.buildDataset(t)
	env.buildImage(t)
	env.writeConfig(t)
	env.startDaemon(t)

	// Order matters: several cases restart the daemon and depend on state left
	// by earlier ones. Subtests keep going on soft-assert failures (assert.*),
	// so a broken case does not mask the rest.
	t.Run("C0_readiness", env.caseReadiness)
	t.Run("C1_metadata_offpath", env.caseMetadataOffpath)
	t.Run("C2_tiny_file", env.caseTinyFile)
	t.Run("C3_partial_range_bounded", env.casePartialRangeBounded)
	t.Run("C4_C5_full_integrity", env.caseFullIntegrity)
	t.Run("C6_daemon_health", env.caseDaemonHealth)
	t.Run("C7_warm_fastpath", env.caseWarmFastpath)
	t.Run("C8_concurrency", env.caseConcurrency)
	t.Run("C9_persistence", env.casePersistence)
	t.Run("C10_graceful_shutdown", env.caseGracefulShutdown)
}

// ------------------------------------------------------------------ setup ----

func (e *nbdEnv) buildDataset(t *testing.T) {
	t.Helper()
	t.Log("building dataset")
	for _, d := range []string{
		filepath.Join(e.sourceDir, "subdir"),
		filepath.Join(e.sourceDir, "many"),
		e.blobDir, e.cacheDir, e.mntDir, e.logDir,
	} {
		require.NoError(t, os.MkdirAll(d, 0755))
	}

	require.NoError(t, os.WriteFile(filepath.Join(e.sourceDir, "hello.txt"), []byte("hello nydus nbd\n"), 0644))
	writeRandomFile(t, filepath.Join(e.sourceDir, "data.bin"), 100*4096)      // ~400K
	writeRandomFile(t, filepath.Join(e.sourceDir, "large.bin"), 64*1024*1024) // 64M
	require.NoError(t, os.WriteFile(filepath.Join(e.sourceDir, "subdir", "nested.txt"), []byte("nested file content\n"), 0644))
	// a fan of small files for the concurrency case (deterministic sizes)
	for i := 1; i <= 48; i++ {
		size := (4 + (i*7)%20) * 4096
		writeRandomFile(t, filepath.Join(e.sourceDir, "many", fmt.Sprintf("f%d.bin", i)), size)
	}

	e.sourceHashes = hashTree(t, e.sourceDir)
	t.Logf("  %d source files hashed", len(e.sourceHashes))
}

func (e *nbdEnv) buildImage(t *testing.T) {
	t.Helper()
	blob := buildNydusFSImageToDir(t, e.nydusBin, e.bootstrap, e.blobDir, e.sourceDir, 4*1024*1024)
	require.FileExists(t, e.bootstrap, "bootstrap not created")
	require.FileExists(t, blob, "blob not created")
	t.Logf("  bootstrap: %s, blob: %s", e.bootstrap, filepath.Base(blob))
}

func (e *nbdEnv) writeConfig(t *testing.T) {
	t.Helper()
	config := fmt.Sprintf(
		"backend:\n  type: local\n  config:\n    dir: %s\nstorage:\n  dir: %s\nprefetch:\n  scope: none\n",
		e.blobDir,
		e.cacheDir,
	)
	require.NoError(t, os.WriteFile(e.configPath, []byte(config), 0644))
	t.Logf("  wrote %s", e.configPath)
}

// ----------------------------------------------------------------- daemon ----

// wipeCache removes every per-blob artifact so the next daemon starts COLD
// (see wipeCacheDir in util.go for why the stale .group.map matters).
func (e *nbdEnv) wipeCache(t *testing.T) {
	t.Helper()
	wipeCacheDir(e.cacheDir)
}

// startDaemon starts a COLD daemon (wipes the cache first) and waits for it
// to mount and log readiness.
func (e *nbdEnv) startDaemon(t *testing.T) {
	t.Helper()
	e.wipeCache(t)
	e.spawnDaemon(t)
}

// spawnDaemon launches the daemon WITHOUT wiping the cache and waits for
// readiness. Used by warm-cache restarts (C9).
func (e *nbdEnv) spawnDaemon(t *testing.T) {
	t.Helper()
	t.Logf("starting nydus nbd daemon on %s", e.device)
	cmd := exec.Command(e.nydusBin, "nbd",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath,
		"--device", e.device,
		"--mountpoint", e.mntDir,
		"--log-level", "debug",
		"--log-dir", e.logDir,
	)
	e.spawnDaemonCmd(t, cmd)

	require.Eventually(t, func() bool {
		select {
		case <-e.daemonExited:
			require.FailNowf(t, "daemon exited during startup", "%s", e.logCorpus())
		default:
		}
		return isMountpoint(e.mntDir) && e.countLogs(`mounted `) > 0
	}, 60*time.Second, time.Second, "daemon did not mount / become ready within 60s:\n%s", e.logCorpus())
	t.Logf("  daemon ready (pid=%d, device=%s)", cmd.Process.Pid, e.device)
}

// waitForDeviceRelease waits for the kernel to finalize NBD device teardown
// after the daemon exits, so the next spawnDaemon can re-open it cleanly.
func (e *nbdEnv) waitForDeviceRelease(t *testing.T) {
	t.Helper()
	waitNbdDeviceRelease(t, e.device)
}

// waitNbdDeviceRelease waits until the kernel reports the NBD device as
// detached (sysfs size back to 0). Shared with TestBench.
func waitNbdDeviceRelease(t *testing.T, device string) {
	t.Helper()
	sysfs := filepath.Join("/sys/block", filepath.Base(device), "size")
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(sysfs)
		if err != nil {
			return true // sysfs path gone — treat as released
		}
		return strings.TrimSpace(string(data)) == "0"
	}, 10*time.Second, 100*time.Millisecond, "NBD device %s not released after daemon exit", device)
}

func (e *nbdEnv) restartDaemonCold(t *testing.T) {
	e.stopDaemon(t)
	e.waitForDeviceRelease(t)
	e.startDaemon(t)
}

// =============================================================== test cases ===

func (e *nbdEnv) caseReadiness(t *testing.T) { // C0
	assert.True(t, isMountpoint(e.mntDir), "mountpoint is live")
	assert.Greater(t, e.countLogs(`nbd service attached`), 0, "daemon logged device attachment")
	assert.Greater(t, e.countLogs(`mounted `), 0, "daemon logged mount")
	// EROFS metadata reads come from the local bootstrap, not blob cache: no
	// whole-blob prefetch may have happened. Some blob-tail allocation IS
	// expected before any file read: the core validates each blob's
	// footer (at the blob's tail) on its first flat-range resolve, and the
	// kernel's block-device open scans the device tail too — every such read
	// rounds outward to whole blob-meta block groups. Bound the cache well below a
	// whole-blob pull rather than at ~zero.
	for _, m := range e.cacheBlobs() {
		assert.Less(t, usedBytes(m), int64(8<<20), "cache %s holds only tail block group fill before any file read", filepath.Base(m))
	}
}

func (e *nbdEnv) caseMetadataOffpath(t *testing.T) { // C1
	before := e.cacheUsed()
	require.NoError(t, exec.Command("ls", "-la", e.mntDir).Run(), "ls mountpoint failed")
	_, err := os.Stat(filepath.Join(e.mntDir, "large.bin"))
	require.NoError(t, err, "stat large.bin failed")
	require.NoError(t, exec.Command("ls", "-la", filepath.Join(e.mntDir, "subdir")).Run(), "ls subdir failed")
	after := e.cacheUsed()
	// metadata comes from the local bootstrap; it must not balloon the blob cache.
	assert.Less(t, after-before, int64(1<<20), "ls/stat serve off bootstrap, negligible blob fill")
}

func (e *nbdEnv) caseTinyFile(t *testing.T) { // C2
	got := sha256File(t, filepath.Join(e.mntDir, "hello.txt"))
	want := sha256File(t, filepath.Join(e.sourceDir, "hello.txt"))
	assert.Equal(t, want, got, "hello.txt byte-exact over NBD")
	content, err := os.ReadFile(filepath.Join(e.mntDir, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello nydus nbd\n", string(content), "hello.txt literal content")
}

func (e *nbdEnv) casePartialRangeBounded(t *testing.T) { // C3 — decisive demand-paging case
	// Fresh cache so the measurement is clean: mid-file 1MiB slices only.
	e.restartDaemonCold(t)
	before := e.cacheUsed()

	mntLarge := filepath.Join(e.mntDir, "large.bin")
	srcLarge := filepath.Join(e.sourceDir, "large.bin")
	for _, skip := range []int64{1, 17, 40, 63} {
		g := sliceSHA(t, mntLarge, skip, 1)
		w := sliceSHA(t, srcLarge, skip, 1)
		assert.Equal(t, w, g, "large.bin[+%dMiB,1MiB] byte-exact", skip)
	}
	after := e.cacheUsed()
	// 4 * 1MiB of logical reads; chunk rounding may amplify, but pulling the
	// whole 64MiB blob per slice would blow way past this.
	assert.Less(t, after-before, int64(24*1024*1024), "partial reads pull bounded ranges, not the whole blob")
	assert.Less(t, after, int64(48*1024*1024), "cache still far below full blob after partial reads")
}

func (e *nbdEnv) caseFullIntegrity(t *testing.T) { // C4 + C5
	before := e.cacheUsed()
	mntHashes := hashTree(t, e.mntDir)
	after := e.cacheUsed()

	assert.Equal(t, e.sourceHashes, mntHashes, "full-tree sha256 == source (every file byte-exact on demand)")
	assert.Greater(t, after, before, "reading the tree grows the blob cache (demand paging)")
	assert.Greater(t, after, int64(40*1024*1024), "cache reaches near-full after reading all data")
}

func (e *nbdEnv) caseDaemonHealth(t *testing.T) { // C6 — daemon health under the workload
	// The authoritative proof that reads go THROUGH the NBD path is
	// correctness (C3/C4/C5); the daemon's error logs are the robust
	// negative checks — none should fire for legitimate reads.
	assert.Equal(t, 0, e.countLogs(`nbd: invalid request magic`), "no bad-magic errors for legit reads")
	assert.Equal(t, 0, e.countLogs(`nbd: short read`), "no short-read errors for legit reads")
	assert.Equal(t, 0, countMatchingLines(e.logCorpus(), nbdReadFailurePattern), "no read/backend failures against the local backend")
	assert.Equal(t, 0, e.countLogs(`nbd: unsupported request type`), "no unsupported-type errors for legit reads")
}

func (e *nbdEnv) caseWarmFastpath(t *testing.T) { // C7 — behavioural warm-path proof
	// Everything is already cached from C4. A warm re-read must serve identical
	// bytes AND allocate ~no new blocks (the core's fully-ready fast path
	// short-circuits the fetch).
	before := e.cacheUsed()
	got := sha256File(t, filepath.Join(e.mntDir, "large.bin"))
	want := sha256File(t, filepath.Join(e.sourceDir, "large.bin"))
	after := e.cacheUsed()
	assert.Equal(t, want, got, "warm re-read is byte-exact")
	assert.Less(t, after-before, int64(1<<20), "warm re-read allocates ~no new cache blocks (fully-ready fast path)")
}

func (e *nbdEnv) caseConcurrency(t *testing.T) { // C8 — stress per-worker request dispatch
	e.restartDaemonCold(t)

	var wg sync.WaitGroup
	var rc atomicInt
	readFile := func(path string) {
		defer wg.Done()
		if f, err := os.Open(path); err != nil {
			rc.set(1)
		} else {
			_, _ = io.Copy(io.Discard, f)
			_ = f.Close()
		}
	}
	manyFiles, _ := filepath.Glob(filepath.Join(e.mntDir, "many", "*.bin"))
	for _, f := range manyFiles {
		wg.Add(1)
		go readFile(f)
	}
	mntLarge := filepath.Join(e.mntDir, "large.bin")
	for _, skip := range []int64{0, 4, 8, 8, 12, 16, 16, 20} {
		wg.Add(1)
		go func(skip int64) {
			defer wg.Done()
			if _, err := readSlice(mntLarge, skip, 2); err != nil {
				rc.set(1)
			}
		}(skip)
	}
	wg.Wait()
	assert.Equal(t, 0, rc.get(), "all concurrent readers returned success (no hang/deadlock)")

	// verify correctness of the fan of small files
	bad := 0
	srcMany, _ := filepath.Glob(filepath.Join(e.sourceDir, "many", "*.bin"))
	for _, f := range srcMany {
		name := filepath.Base(f)
		if sha256File(t, filepath.Join(e.mntDir, "many", name)) != sha256File(t, f) {
			bad++
		}
	}
	assert.Equal(t, 0, bad, "every concurrently-read small file is byte-exact")
	assert.True(t, e.daemonAlive(), "daemon still alive after stress")
}

func (e *nbdEnv) casePersistence(t *testing.T) { // C9 — warm cache survives a restart
	// Warm the whole tree, then restart WITHOUT clearing the cache dir.
	_ = readWhole(t, filepath.Join(e.mntDir, "large.bin"))
	_ = readWhole(t, filepath.Join(e.mntDir, "data.bin"))
	manyFiles, _ := filepath.Glob(filepath.Join(e.mntDir, "many", "*.bin"))
	for _, f := range manyFiles {
		_ = readWhole(t, f)
	}

	before := e.cacheUsed()
	// restart preserving cache: spawn without the cold wipe.
	e.stopDaemon(t)
	e.waitForDeviceRelease(t)
	t.Log("  restarting daemon with warm cache (no wipe)")
	e.spawnDaemon(t)

	got := sha256File(t, filepath.Join(e.mntDir, "large.bin"))
	want := sha256File(t, filepath.Join(e.sourceDir, "large.bin"))
	assert.Equal(t, want, got, "large.bin still byte-exact after restart")
	after := e.cacheUsed()
	// Warm cache: re-reading the same data should not grow the cache (the
	// core's persisted block group map short-circuits the fetch).
	assert.Less(t, after-before, int64(1<<20), "warm cache re-serves with no new cache allocation after restart")
}

func (e *nbdEnv) caseGracefulShutdown(t *testing.T) { // C10
	require.NotNil(t, e.daemonCmd, "daemon not running")
	proc := e.daemonCmd.Process
	_ = proc.Signal(syscall.SIGTERM)

	// Wait on daemonExited (closed by the single cmd.Wait goroutine spawned in
	// spawnDaemon). A second concurrent Wait on the same exec.Cmd would race
	// and can return "Wait was already called" before the process has exited.
	exited := false
	select {
	case <-e.daemonExited:
		exited = true
	case <-time.After(20 * time.Second):
		_ = proc.Kill()
		<-e.daemonExited
	}
	e.daemonCmd = nil

	assert.True(t, exited, "daemon exits on SIGTERM")
	assert.Greater(t, e.countLogs(`received signal`), 0, "shutdown path logged")
	time.Sleep(time.Second)
	assert.False(t, isMountpoint(e.mntDir), "mountpoint cleanly unmounted (no leak)")
}

// ---------------------------------------------------------------- cleanup ----

func (e *nbdEnv) cleanup(t *testing.T) {
	if e.daemonCmd != nil && e.daemonCmd.Process != nil {
		_ = e.daemonCmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- e.daemonCmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = e.daemonCmd.Process.Kill()
			<-done
		}
		e.daemonCmd = nil
	}
	// a reader denied mid-fault (EIO) can keep the mount busy; never hang.
	if isMountpoint(e.mntDir) {
		if exec.Command("umount", e.mntDir).Run() != nil {
			_ = exec.Command("umount", "-l", e.mntDir).Run()
		}
	}
}

// ---------------------------------------------------------------- helpers ----

func (e *nbdEnv) daemonAlive() bool {
	return e.daemonCmd != nil && e.daemonCmd.ProcessState == nil
}

// cacheBlobs returns all *.blob.data files in the cache dir.
func (e *nbdEnv) cacheBlobs() []string {
	matches, _ := filepath.Glob(filepath.Join(e.cacheDir, "*.blob.data"))
	return matches
}

// cacheUsed sums the allocated bytes of every *.blob.data file — the
// demand-paging signal (a hole file reports ~0 until a chunk is fetched).
func (e *nbdEnv) cacheUsed() int64 {
	var total int64
	for _, m := range e.cacheBlobs() {
		total += usedBytes(m)
	}
	return total
}

// logCorpus concatenates the daemon console log and every file under logDir.
func (e *nbdEnv) logCorpus() string {
	var b strings.Builder
	b.Write(readFileOrEmpty(e.daemonLog))
	entries, _ := os.ReadDir(e.logDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			b.Write(readFileOrEmpty(filepath.Join(e.logDir, entry.Name())))
		}
	}
	return b.String()
}

// countLogs counts lines across every log sink matching the pattern.
func (e *nbdEnv) countLogs(pattern string) int {
	return countMatchingLines(e.logCorpus(), regexp.MustCompile(pattern))
}

func TestCountMatchingLinesCountsOnlyNbdReadFailures(t *testing.T) {
	corpus := strings.Join([]string{
		"INFO nbd service attached to /dev/nbd0",
		"WARN nbd: failed to read request header: unexpected EOF",
		"WARN nbd: failed to handle request: broken pipe",
		"WARN nbd: read [0x0, +4096) failed: input/output error",
	}, "\n")

	assert.Equal(t, 1, countMatchingLines(corpus, nbdReadFailurePattern))
}

// erofsSupported reports whether the running kernel has EROFS filesystem
// support (either built-in or as a module).
func erofsSupported() bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "\terofs\n")
}

// findFreeNbdDevice finds a free /dev/nbdX by scanning /sys/block/nbdN/size
// for "0" (unattached). Loads the nbd module if needed.
func findFreeNbdDevice() (string, error) {
	// Ensure the nbd module is loaded.
	if _, err := os.Stat("/dev/nbd0"); err != nil {
		if exec.Command("modprobe", "nbd").Run() != nil {
			return "", fmt.Errorf("nbd module not available and modprobe failed: %w", err)
		}
	}
	// Scan /sys/block/nbdN/size for a free device (size == 0 means unattached).
	for i := 0; i < 16; i++ {
		dev := fmt.Sprintf("/dev/nbd%d", i)
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		sizePath := fmt.Sprintf("/sys/block/nbd%d/size", i)
		data, err := os.ReadFile(sizePath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == "0" {
			return dev, nil
		}
	}
	return "", fmt.Errorf("no free /dev/nbdX device (nbd0-nbd15 all in use)")
}
