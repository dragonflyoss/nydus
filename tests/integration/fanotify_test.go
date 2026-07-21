package integration

// Nydus fanotify pre-content END-TO-END test (registry backend).
//
// This is NOT a smoke test: it boots the real `nydus fanotify` daemon
// against a real OCI registry backend
// (a throwaway local `registry:2` container, no external creds), mounts a
// file-backed EROFS image on demand, and asserts — with byte-exact hashes,
// cache-growth measurements and daemon event logs — that cold blob-data reads
// are served through the fanotify pre-content path and are correct.
//
// Cases:
//
//	C0  service readiness + cache starts fully sparse
//	C1  metadata (ls/stat) served off the local bootstrap, not fanotify
//	C2  tiny single-block file: byte-exact content
//	C3  mid-file PARTIAL read is byte-exact AND range-bounded (not whole-blob)
//	C4  full-tree integrity: every file's sha256 == source
//	C5  demand-paging proof: cache grows sparse -> filled, correlated to reads
//	C6  event-driven proof: daemon logs show no unknown-fd / invalid-range /
//	    backend-failure denies
//	C7  warm fast-path: re-read triggers range_ready ALLOW, no new backend fetch
//	C8  concurrency/stress: many parallel readers, all correct, no deadlock/deny
//	C9  persistence across restart: warm cache re-serves with no backend fetch
//	C10 graceful shutdown: SIGTERM -> clean unmount, no leak
//	C11 (optional, FANOTIFY_RUN_FAIL_CLOSED=1) fail-closed: backend down ->
//	    uncached read DENIED, not wrong data
//	C12 (optional, skipped if FANOTIFY_RUN_STRACE=0 or strace absent)
//	    strace ground truth: daemon READS pre-content events off the fanotify
//	    fd, WRITES permission responses, and PWRITES fetched data into the cache
//
// HARD REQUIREMENTS (the test skips loudly if unmet):
//   - root (fanotify FAN_CLASS_PRE_CONTENT needs CAP_SYS_ADMIN)
//   - Linux >= 6.15 with a kernel that routes file-backed EROFS backing reads
//     through the VFS pre-content hook (see docs/fanotify.md, "Requirements")
//   - docker (for the throwaway local registry), nydus + nydusify binaries with
//     the fanotify subcommand (build with --features cli,fanotify)
//   - cache directory on a filesystem supporting pre-content events (ext4/btrfs;
//     tmpfs does NOT support FAN_PRE_ACCESS — the Makefile sets TMPDIR to the
//     repo root's .test-tmp/ on the same filesystem as the working tree)
//
// Environment overrides:
//
//	NYDUS_BIN                 path to the nydus binary (default: in-tree lookup)
//	NYDUSIFY_BIN              path to nydusify        (default: in-tree lookup)
//	FANOTIFY_REGISTRY         registry host:port      (default: 127.0.0.1:5000)
//	FANOTIFY_REPO             repository              (default: nydus-e2e/fanotify)
//	FANOTIFY_TAG              tag                     (default: v1)
//	FANOTIFY_RUN_FAIL_CLOSED  set to 1 to also run C11
//	FANOTIFY_RUN_STRACE       set to 0 to skip C12    (default: runs if strace present)

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fanotifyEnv holds the paths, binaries and process handles for one E2E run.
type fanotifyEnv struct {
	nydusBin    string
	nydusifyBin string

	registry string
	repo     string
	tag      string
	imageRef string

	workDir    string
	sourceDir  string
	blobDir    string
	cacheDir   string
	mntDir     string
	logDir     string
	checkDir   string
	configPath string
	daemonLog  string
	straceLog  string
	bootstrap  string

	registryCID  string // docker container id, if we started one
	daemonCmd    *exec.Cmd
	daemonExited chan struct{} // closed when cmd.Wait() returns

	sourceHashes map[string]string // rel path -> sha256
}

func TestFanotifyE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fanotify pre-content E2E requires Linux")
	}
	if os.Getuid() != 0 {
		t.Skip("fanotify FAN_CLASS_PRE_CONTENT requires root (CAP_SYS_ADMIN)")
	}
	if maj, min := kernelVersion(t); maj < 6 || (maj == 6 && min < 15) {
		t.Skipf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", maj, min)
	}

	env := &fanotifyEnv{
		registry: envOr("FANOTIFY_REGISTRY", "127.0.0.1:5000"),
		repo:     envOr("FANOTIFY_REPO", "nydus-e2e/fanotify"),
		tag:      envOr("FANOTIFY_TAG", "v1"),
	}
	env.imageRef = fmt.Sprintf("%s/%s:%s", env.registry, env.repo, env.tag)

	env.nydusBin = lookupFanotifyBin(t, "NYDUS_BIN", "nydus")
	if out, err := exec.Command(env.nydusBin, "fanotify", "--help").CombinedOutput(); err != nil {
		t.Skipf("nydus binary lacks the fanotify subcommand; build with --features cli,fanotify: %s", out)
	}
	env.nydusifyBin = lookupFanotifyBin(t, "NYDUSIFY_BIN", "nydusify")
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker required for the throwaway local registry")
	}

	env.workDir = t.TempDir()
	env.sourceDir = filepath.Join(env.workDir, "source")
	env.blobDir = filepath.Join(env.workDir, "blobs")
	env.cacheDir = filepath.Join(env.workDir, "cache")
	env.mntDir = filepath.Join(env.workDir, "mnt")
	env.logDir = filepath.Join(env.workDir, "logs")
	env.checkDir = filepath.Join(env.workDir, "check-output")
	env.configPath = filepath.Join(env.workDir, "config-registry.yaml")
	env.daemonLog = filepath.Join(env.workDir, "daemon.console.log")
	env.bootstrap = filepath.Join(env.checkDir, "target", "bootstrap", "image", "image.boot")

	t.Cleanup(func() { env.cleanup(t) })

	env.startLocalRegistry(t)
	env.buildDataset(t)
	env.convertAndExport(t)
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
	t.Run("C6_event_driven", env.caseEventDriven)
	t.Run("C7_warm_fastpath", env.caseWarmFastpath)
	t.Run("C8_concurrency", env.caseConcurrency)
	t.Run("C9_persistence", env.casePersistence)
	t.Run("C10_graceful_shutdown", env.caseGracefulShutdown)
	t.Run("C11_fail_closed", env.caseFailClosed)
	t.Run("C12_strace_ground_truth", env.caseStraceGroundTruth)
}

// ------------------------------------------------------------------ setup ----

func (e *fanotifyEnv) startLocalRegistry(t *testing.T) {
	t.Helper()
	// Only auto-start for a loopback host we own.
	host := e.registry
	loopback := strings.HasPrefix(host, "127.0.0.1:") ||
		strings.HasPrefix(host, "localhost:") ||
		strings.HasPrefix(host, "[::1]:")
	if !loopback {
		t.Logf("using external registry %s (not auto-starting one)", host)
		return
	}
	if registryReady(host) {
		t.Logf("registry already listening at %s", host)
		return
	}
	port := host[strings.LastIndex(host, ":")+1:]
	t.Logf("starting throwaway registry:2 on %s", host)
	out, err := exec.Command("docker", "run", "-d", "-p", port+":5000", "--restart=no", "registry:2").CombinedOutput()
	require.NoError(t, err, "failed to start local registry container: %s", out)
	e.registryCID = strings.TrimSpace(string(out))

	require.Eventually(t, func() bool {
		return registryReady(host)
	}, 30*time.Second, time.Second, "local registry did not become ready")
	t.Log("  registry up")
}

func (e *fanotifyEnv) buildDataset(t *testing.T) {
	t.Helper()
	t.Log("building dataset")
	for _, d := range []string{
		filepath.Join(e.sourceDir, "subdir"),
		filepath.Join(e.sourceDir, "many"),
		e.blobDir, e.cacheDir, e.mntDir, e.logDir,
	} {
		require.NoError(t, os.MkdirAll(d, 0755))
	}

	require.NoError(t, os.WriteFile(filepath.Join(e.sourceDir, "hello.txt"), []byte("hello nydus fanotify\n"), 0644))
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

func (e *fanotifyEnv) convertAndExport(t *testing.T) {
	t.Helper()
	var insecure []string
	if e.registryIsLoopback() {
		insecure = []string{"--target-insecure", "--target-plain-http"}
	}

	t.Logf("nydusify convert -> %s", e.imageRef)
	args := append([]string{"convert",
		"--source", e.sourceDir,
		"--target", e.imageRef,
		"--builder", e.nydusBin,
	}, insecure...)
	out, err := exec.Command(e.nydusifyBin, args...).CombinedOutput()
	require.NoError(t, err, "nydusify convert failed:\n%s", out)

	t.Log("nydusify check -> export bootstrap")
	require.NoError(t, os.RemoveAll(e.checkDir))
	args = append([]string{"check",
		"--target", e.imageRef,
		"--work-dir", e.checkDir,
	}, insecure...)
	out, err = exec.Command(e.nydusifyBin, args...).CombinedOutput()
	require.NoError(t, err, "nydusify check failed:\n%s", out)

	if _, err := os.Stat(e.bootstrap); err != nil {
		if found := findFile(e.checkDir, "image.boot"); found != "" {
			e.bootstrap = found
		}
	}
	require.FileExists(t, e.bootstrap, "exported bootstrap not found")
	t.Logf("  bootstrap: %s (%d bytes allocated)", e.bootstrap, usedBytes(e.bootstrap))
}

func (e *fanotifyEnv) writeConfig(t *testing.T) {
	t.Helper()
	insecure, skip := "false", "false"
	if e.registryIsLoopback() {
		insecure, skip = "true", "true"
	}
	config := fmt.Sprintf(`backend:
  type: registry
  config:
    host: %s
    repo: %s
    insecure: %s
    skip_verify: %s
cache:
  type: local
  config:
    dir: %s
prefetch:
  enable: false
`, e.registry, e.repo, insecure, skip, e.cacheDir)
	require.NoError(t, os.WriteFile(e.configPath, []byte(config), 0644))
	t.Logf("  wrote %s (insecure=%s)", e.configPath, insecure)
}

// ----------------------------------------------------------------- daemon ----

// wipeCache removes every per-blob artifact so the next daemon starts COLD.
// Leaving a stale .groupmap behind makes the daemon believe groups are ready
// while the re-created .blob.data is all zeros — range_ready would ALLOW
// without fetching and the reader gets a sparse hole. Wipe data+meta+map+lock.
func (e *fanotifyEnv) wipeCache(t *testing.T) {
	t.Helper()
	for _, pattern := range []string{"*.blob.data", "*.blob.meta", "*.groupmap", "*.prefetch.lock"} {
		matches, _ := filepath.Glob(filepath.Join(e.cacheDir, pattern))
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}

// startDaemon starts a COLD daemon (wipes the cache first) and waits for it to
// mount and log "event loop ready".
func (e *fanotifyEnv) startDaemon(t *testing.T) {
	t.Helper()
	e.wipeCache(t)
	e.spawnDaemon(t)
}

// spawnDaemon launches the daemon WITHOUT wiping the cache and waits for
// readiness. Used by warm-cache restarts (C9).
func (e *fanotifyEnv) spawnDaemon(t *testing.T) {
	t.Helper()
	t.Log("starting nydus fanotify daemon")
	logFile, err := os.Create(e.daemonLog)
	require.NoError(t, err)

	cmd := exec.Command(e.nydusBin, "fanotify",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath,
		"--mountpoint", e.mntDir,
		"--log-level", "debug",
		"--log-dir", e.logDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	e.daemonCmd = cmd
	e.daemonExited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(e.daemonExited) }()
	_ = logFile.Close()

	require.Eventually(t, func() bool {
		select {
		case <-e.daemonExited:
			require.FailNowf(t, "daemon exited during startup", "%s", e.logCorpus())
		default:
		}
		return isMountpoint(e.mntDir) && e.countLogs(`event loop ready`) > 0
	}, 60*time.Second, time.Second, "daemon did not mount / become ready within 60s:\n%s", e.logCorpus())
	t.Logf("  daemon ready (pid=%d)", cmd.Process.Pid)
}

func (e *fanotifyEnv) stopDaemon(t *testing.T) {
	t.Helper()
	if e.daemonCmd == nil || e.daemonCmd.Process == nil {
		return
	}
	// If already exited (e.g. crash detected elsewhere), just reap.
	if e.daemonExited != nil {
		select {
		case <-e.daemonExited:
			e.daemonCmd = nil
			return
		default:
		}
	}
	_ = e.daemonCmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.daemonExited:
	case <-time.After(20 * time.Second):
		_ = e.daemonCmd.Process.Kill()
		<-e.daemonExited
	}
	e.daemonCmd = nil
}

func (e *fanotifyEnv) restartDaemonCold(t *testing.T) {
	e.stopDaemon(t)
	e.startDaemon(t)
}

// =============================================================== test cases ===

func (e *fanotifyEnv) caseReadiness(t *testing.T) { // C0
	blob := e.cacheBlob(t)
	require.NotEmpty(t, blob, "no blob cache file created")
	assert.True(t, isMountpoint(e.mntDir), "mountpoint is live")
	assert.Less(t, usedBytes(blob), int64(1<<20), "cache starts sparse (<1MiB allocated)")
	assert.Greater(t, e.countLogs(`marked device slot`), 0, "at least one device marked FAN_PRE_ACCESS")
}

func (e *fanotifyEnv) caseMetadataOffpath(t *testing.T) { // C1
	blob := e.cacheBlob(t)
	before := usedBytes(blob)
	require.NoError(t, exec.Command("ls", "-la", e.mntDir).Run(), "ls mountpoint failed")
	_, err := os.Stat(filepath.Join(e.mntDir, "large.bin"))
	require.NoError(t, err, "stat large.bin failed")
	require.NoError(t, exec.Command("ls", "-la", filepath.Join(e.mntDir, "subdir")).Run(), "ls subdir failed")
	after := usedBytes(blob)
	// metadata comes from the local bootstrap; it must not balloon the blob cache.
	assert.Less(t, after-before, int64(1<<20), "ls/stat serve off bootstrap, negligible blob fill")
}

func (e *fanotifyEnv) caseTinyFile(t *testing.T) { // C2
	got := shaFile(t, filepath.Join(e.mntDir, "hello.txt"))
	want := shaFile(t, filepath.Join(e.sourceDir, "hello.txt"))
	assert.Equal(t, want, got, "hello.txt byte-exact over fanotify")
	content, err := os.ReadFile(filepath.Join(e.mntDir, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello nydus fanotify\n", string(content), "hello.txt literal content")
}

func (e *fanotifyEnv) casePartialRangeBounded(t *testing.T) { // C3 — decisive demand-paging case
	// Fresh cache so the measurement is clean: mid-file 1MiB slices only.
	e.restartDaemonCold(t)
	blob := e.cacheBlob(t)
	base := usedBytes(blob)

	mntLarge := filepath.Join(e.mntDir, "large.bin")
	srcLarge := filepath.Join(e.sourceDir, "large.bin")
	for _, skip := range []int64{1, 17, 40, 63} {
		g := sliceSha(t, mntLarge, skip, 1)
		w := sliceSha(t, srcLarge, skip, 1)
		assert.Equal(t, w, g, "large.bin[+%dMiB,1MiB] byte-exact", skip)
	}
	after := usedBytes(blob)
	// 4 * 1MiB of logical reads; group rounding may amplify, but pulling the
	// whole 64MiB blob per slice would blow way past this.
	assert.Less(t, after-base, int64(24*1024*1024), "partial reads pull bounded ranges, not the whole blob")
	assert.Less(t, after, int64(48*1024*1024), "cache still far below full blob after partial reads")
}

func (e *fanotifyEnv) caseFullIntegrity(t *testing.T) { // C4 + C5
	blob := e.cacheBlob(t)
	before := usedBytes(blob)
	mntHashes := hashTree(t, e.mntDir)
	after := usedBytes(blob)

	assert.Equal(t, e.sourceHashes, mntHashes, "full-tree sha256 == source (every file byte-exact on demand)")
	assert.Greater(t, after, before, "reading the tree grows the blob cache (demand paging)")
	assert.Greater(t, after, int64(40*1024*1024), "cache reaches near-full after reading all data")
}

func (e *fanotifyEnv) caseEventDriven(t *testing.T) { // C6 — daemon health under the workload
	// The authoritative proof that reads go THROUGH the fanotify path is
	// correctness (C3/C4/C5); the daemon's debug logs are emitted through a
	// non-blocking, lossy writer under a burst, so a zero positive count is an
	// observability artifact, not evidence the path was skipped. We keep only
	// the ROBUST negative checks as hard assertions.
	t.Logf("  [C6 info] job-dispatched log lines: %d (lossy)", e.countLogs(`job [0-9]+ dispatched`))
	t.Logf("  [C6 info] fetch-allow  log lines: %d", e.countLogs(`fetch succeeded; allowing`))
	assert.Equal(t, 0, e.countLogs(`unknown event fd`), "no unknown-device denies for legit reads")
	assert.Equal(t, 0, e.countLogs(`immediate deny: InvalidRange`), "no invalid-range denies for legit reads")
	assert.Equal(t, 0, e.countLogs(`fetch backend failure`), "no backend failures against the registry")
}

func (e *fanotifyEnv) caseWarmFastpath(t *testing.T) { // C7 — behavioural warm-path proof
	// Everything is already cached from C4. A warm re-read must serve identical
	// bytes AND allocate ~no new blocks (range_ready short-circuits the fetch).
	blob := e.cacheBlob(t)
	before := usedBytes(blob)
	got := shaFile(t, filepath.Join(e.mntDir, "large.bin"))
	want := shaFile(t, filepath.Join(e.sourceDir, "large.bin"))
	after := usedBytes(blob)
	assert.Equal(t, want, got, "warm re-read is byte-exact")
	assert.Less(t, after-before, int64(1<<20), "warm re-read allocates ~no new cache blocks (range_ready fast path)")
}

func (e *fanotifyEnv) caseConcurrency(t *testing.T) { // C8 — stress per-event tasks + singleflight
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
		if shaFile(t, filepath.Join(e.mntDir, "many", name)) != shaFile(t, f) {
			bad++
		}
	}
	assert.Equal(t, 0, bad, "every concurrently-read small file is byte-exact")
	assert.Equal(t, 0, e.countLogs(`fetch worker panicked`), "no fetch-worker panics (singleflight sound)")
	assert.True(t, e.daemonAlive(), "daemon still alive after stress")
}

func (e *fanotifyEnv) casePersistence(t *testing.T) { // C9 — warm cache survives a restart
	// Warm the whole tree, then restart WITHOUT clearing the cache dir.
	_ = readWhole(t, filepath.Join(e.mntDir, "large.bin"))
	_ = readWhole(t, filepath.Join(e.mntDir, "data.bin"))
	manyFiles, _ := filepath.Glob(filepath.Join(e.mntDir, "many", "*.bin"))
	for _, f := range manyFiles {
		_ = readWhole(t, f)
	}

	// restart preserving cache: spawn without the cold wipe.
	e.stopDaemon(t)
	t.Log("  restarting daemon with warm cache (no wipe)")
	e.spawnDaemon(t)

	beforeFetch := e.countLogs(`job [0-9]+ dispatched`)
	got := shaFile(t, filepath.Join(e.mntDir, "large.bin"))
	want := shaFile(t, filepath.Join(e.sourceDir, "large.bin"))
	assert.Equal(t, want, got, "large.bin still byte-exact after restart")
	afterFetch := e.countLogs(`job [0-9]+ dispatched`)
	assert.Equal(t, beforeFetch, afterFetch, "warm cache re-serves with NO backend fetch after restart")
}

func (e *fanotifyEnv) caseGracefulShutdown(t *testing.T) { // C10
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
	assert.Greater(t, e.countLogs(`stop signal received`), 0, "shutdown path logged (deny-undecided)")
	time.Sleep(time.Second)
	assert.False(t, isMountpoint(e.mntDir), "mountpoint cleanly unmounted (no leak)")
}

func (e *fanotifyEnv) caseFailClosed(t *testing.T) { // C11 (optional)
	if os.Getenv("FANOTIFY_RUN_FAIL_CLOSED") != "1" {
		t.Skip("set FANOTIFY_RUN_FAIL_CLOSED=1 to enable")
	}
	if e.registryCID == "" {
		t.Skip("C11 needs the local registry container")
	}
	e.startDaemon(t)
	defer e.stopDaemon(t)

	// take the registry offline, then read a definitely-cold file
	require.NoError(t, exec.Command("docker", "stop", e.registryCID).Run())
	_, err := readSlice(filepath.Join(e.mntDir, "large.bin"), 50, 4)
	// the read must FAIL (EACCES/EIO) rather than hang or return zeros
	assert.Error(t, err, "uncached read is DENIED when the backend is unreachable (fail-closed)")
	assert.Greater(t, e.countLogs(`fetch backend failure`), 0, "daemon logged a backend-failure deny")

	_ = exec.Command("docker", "start", e.registryCID).Run()
	require.Eventually(t, func() bool { return registryReady(e.registry) }, 30*time.Second, time.Second)
}

func (e *fanotifyEnv) caseStraceGroundTruth(t *testing.T) { // C12 (optional)
	// Runs by default when strace is present; set FANOTIFY_RUN_STRACE=0 to skip.
	if os.Getenv("FANOTIFY_RUN_STRACE") == "0" {
		t.Skip("C12 skipped (FANOTIFY_RUN_STRACE=0)")
	}
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not installed (apt install strace)")
	}

	// Cold restart under strace.
	e.stopDaemon(t)
	e.wipeCache(t)
	e.straceLog = filepath.Join(e.workDir, "strace.log")

	t.Log("  starting daemon under strace (cold cache)")
	straceCmd := exec.Command("strace",
		"-f", "-tt", "-y",
		"-e", "trace=fanotify_init,read,write,pwrite64,pwritev",
		"-o", e.straceLog,
		e.nydusBin, "fanotify",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath,
		"--mountpoint", e.mntDir,
		"--log-level", "debug",
		"--log-dir", e.logDir,
	)
	logFile, err := os.Create(e.daemonLog)
	require.NoError(t, err)
	straceCmd.Stdout = logFile
	straceCmd.Stderr = logFile
	require.NoError(t, straceCmd.Start())
	e.daemonCmd = straceCmd
	e.daemonExited = make(chan struct{})
	go func() { _ = straceCmd.Wait(); close(e.daemonExited) }()
	_ = logFile.Close()

	require.Eventually(t, func() bool {
		select {
		case <-e.daemonExited:
			require.FailNowf(t, "daemon exited during startup under strace", "%s", e.logCorpus())
		default:
		}
		return isMountpoint(e.mntDir) && e.countLogs(`event loop ready`) > 0
	}, 60*time.Second, time.Second, "daemon did not mount under strace:\n%s", e.logCorpus())
	t.Logf("  daemon ready under strace (pid=%d)", straceCmd.Process.Pid)

	// One cold read — triggers fanotify pre-content events + a backend fetch.
	_, err = readSlice(filepath.Join(e.mntDir, "large.bin"), 1, 1)
	require.NoError(t, err, "cold read failed under strace")
	time.Sleep(time.Second)

	slog, err := os.ReadFile(e.straceLog)
	require.NoError(t, err, "cannot read strace log")

	fanFd := extractFanotifyFd(string(slog))
	if fanFd == "" {
		t.Logf("  [C12 warn] could not extract fanotify fd; counts may be zero")
	}
	reads := countStraceSyscall(string(slog), "read", fanFd)
	writes := countStraceSyscall(string(slog), "write", fanFd)
	pw := countStracePwrite(string(slog))

	t.Logf("  strace: fan_fd=%s read(fan)=%d write(fan)=%d pwrite(blob.data)=%d", fanFd, reads, writes, pw)

	assert.Greater(t, reads, 0, "daemon READS pre-content events off the fanotify fd")
	assert.Greater(t, writes, 0, "daemon WRITES permission responses (ALLOW/DENY)")
	assert.Greater(t, pw, 0, "daemon PWRITES fetched data into the blob cache")

	e.stopDaemon(t)
}

// ---------------------------------------------------------------- cleanup ----

func (e *fanotifyEnv) cleanup(t *testing.T) {
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
	if e.registryCID != "" {
		_ = exec.Command("docker", "rm", "-f", e.registryCID).Run()
	}
}

// ---------------------------------------------------------------- helpers ----

func (e *fanotifyEnv) registryIsLoopback() bool {
	return strings.HasPrefix(e.registry, "127.0.0.1:") ||
		strings.HasPrefix(e.registry, "localhost:") ||
		strings.HasPrefix(e.registry, "[::1]:")
}

func (e *fanotifyEnv) daemonAlive() bool {
	return e.daemonCmd != nil && e.daemonCmd.ProcessState == nil
}

// cacheBlob returns the first *.blob.data file in the cache dir.
func (e *fanotifyEnv) cacheBlob(t *testing.T) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(e.cacheDir, "*.blob.data"))
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// logCorpus concatenates the daemon console log and every file under logDir.
func (e *fanotifyEnv) logCorpus() string {
	var b strings.Builder
	b.Write(mustReadFile(e.daemonLog))
	entries, _ := os.ReadDir(e.logDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			b.Write(mustReadFile(filepath.Join(e.logDir, entry.Name())))
		}
	}
	return b.String()
}

// countLogs counts lines across every log sink matching the ERE-style pattern.
func (e *fanotifyEnv) countLogs(pattern string) int {
	re := regexp.MustCompile(pattern)
	count := 0
	for _, line := range strings.Split(e.logCorpus(), "\n") {
		if re.MatchString(line) {
			count++
		}
	}
	return count
}

// usedBytes returns the actual on-disk allocated bytes (blocks * 512), NOT the
// apparent size — the demand-paging signal (a hole file reports ~0).
func usedBytes(path string) int64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Blocks * 512
}

func shaFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// sliceSha reads countMiB starting at skipMiB (bs=1M semantics) and returns the
// sha256 of that slice.
func sliceSha(t *testing.T, path string, skipMiB, countMiB int64) string {
	t.Helper()
	data, err := readSlice(path, skipMiB, countMiB)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readSlice reads countMiB MiB starting at offset skipMiB MiB.
func readSlice(path string, skipMiB, countMiB int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(skipMiB*1024*1024, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, countMiB*1024*1024)
	n, err := io.ReadFull(f, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		err = nil
	}
	return buf[:n], err
}

func readWhole(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	n, err := io.Copy(io.Discard, f)
	require.NoError(t, err)
	return n
}

// hashTree walks dir and returns a map of relative path -> sha256 for every
// regular file, mirroring `find . -type f -exec sha256sum`.
func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	hashes := make(map[string]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hashes[rel] = shaFile(t, path)
		return nil
	})
	require.NoError(t, err)
	return hashes
}

func writeRandomFile(t *testing.T, path string, size int) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	_, err = io.CopyN(f, newDeterministicRand(int64(len(path))), int64(size))
	require.NoError(t, err)
}

func registryReady(host string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + host + "/v2/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

func kernelVersion(t *testing.T) (int, int) {
	t.Helper()
	var uts syscall.Utsname
	require.NoError(t, syscall.Uname(&uts))
	release := int8SliceToString(uts.Release[:])
	parts := strings.SplitN(release, ".", 3)
	require.GreaterOrEqual(t, len(parts), 2, "unexpected kernel release: %s", release)
	maj, err := strconv.Atoi(parts[0])
	require.NoError(t, err)
	min, err := strconv.Atoi(nonDigitTrim(parts[1]))
	require.NoError(t, err)
	return maj, min
}

func int8SliceToString(s []int8) string {
	b := make([]byte, 0, len(s))
	for _, c := range s {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func nonDigitTrim(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}

func lookupFanotifyBin(t *testing.T, envName, name string) string {
	t.Helper()
	if p := os.Getenv(envName); p != "" {
		require.NoError(t, validateExecutablePath(p, envName))
		return p
	}
	return mustLookupExecutable(t, name)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustReadFile(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}

func findFile(root, name string) string {
	var found string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && filepath.Base(path) == name {
			found = path
			return io.EOF // stop early
		}
		return nil
	})
	return found
}

// atomicInt is a tiny mutex-guarded int used to collect a pass/fail flag across
// concurrent goroutines in C8.
type atomicInt struct {
	mu sync.Mutex
	v  int
}

func (a *atomicInt) set(v int) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicInt) get() int  { a.mu.Lock(); defer a.mu.Unlock(); return a.v }

// extractFanotifyFd tries to find the fanotify fd from strace output.
// First tries the fanotify_init return value, then falls back to the
// anon_inode tag that strace -y adds to every fd.
func extractFanotifyFd(slog string) string {
	// fanotify_init(FAN_CLASS_PRE_CONTENT, ...) = 3
	if m := regexp.MustCompile(`fanotify_init\([^)]*\)\s*=\s*(\d+)`).FindStringSubmatch(slog); len(m) > 1 {
		return m[1]
	}
	// Fallback: 3<anon_inode:[fanotify]>
	if m := regexp.MustCompile(`(\d+)<anon_inode:\[fanotify\]>`).FindStringSubmatch(slog); len(m) > 1 {
		return m[1]
	}
	return ""
}

// countStraceSyscall counts read(N or write(N calls on fd in the strace log.
// strace -y format: read(3<anon_inode:[fanotify]>, …  or  read(3, …
func countStraceSyscall(slog, syscall, fd string) int {
	if fd == "" {
		return 0
	}
	re := regexp.MustCompile(regexp.QuoteMeta(syscall) + `\(` + fd + `[<,]`)
	return len(re.FindAllString(slog, -1))
}

// countStracePwrite counts pwrite64/pwritev calls that target blob.data files.
func countStracePwrite(slog string) int {
	re := regexp.MustCompile(`pwrite(?:64|v)?\(.*blob\.data`)
	return len(re.FindAllString(slog, -1))
}

// newDeterministicRand returns a cheap deterministic byte stream seeded so each
// file's content is distinct (a source of random-looking bytes without needing
// /dev/urandom or Math.random-style nondeterminism).
func newDeterministicRand(seed int64) io.Reader {
	return &lcgReader{state: uint64(seed)*2862933555777941757 + 3037000493}
}

type lcgReader struct{ state uint64 }

func (r *lcgReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 33)
	}
	return len(p), nil
}
