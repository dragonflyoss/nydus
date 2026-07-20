package integration

// Fanotify vs FUSE performance comparison benchmark (registry backend).
//
// Both modes mount the same registry-backed nydus image so the comparison
// is a like-for-like read-path measurement: fanotify serves data through
// the kernel EROFS path (FAN_PRE_ACCESS → groupmap check → FAN_ALLOW →
// kernel reads from ext4 cache file), while FUSE serves every read through
// the userspace daemon (FUSE request → groupmap check → pread cache file →
// FUSE reply).
//
// Methodology (per mode):
//
//  1. prewarm: read the whole target file → nydus cache + groupmap filled.
//     No further registry fetch occurs; all subsequent reads hit groupmap.
//  2. warmup page cache: short seq read → kernel page cache fully warm.
//  3. warm benchmarks (no dropCaches): fully warm (nydus cache + page cache).
//     Measures pure read-path overhead: fanotify event handling + kernel
//     ext4 read vs FUSE request/reply + pread — all memory hits, no I/O.
//  4. cold-page benchmarks (dropCaches before each job): warm nydus cache,
//     cold page cache. Measures read path + kernel ext4 read from cold
//     page cache (disk/readahead).
//
// The two columns are:
//   - warm      = steady-state (container running, all data in memory)
//   - cold-page  = memory pressure (page cache reclaimed, nydus cache warm)
//
// Setup mirrors fanotify_test.go: a throwaway local registry:2 container,
// nydusify convert of a real OCI image, then mount via --bootstrap + --config
// (backend: type: registry) for both modes. The source image is specified by
// FANOTIFY_PERF_SOURCE_IMAGE (skip if unset).
//
// Activation: FANOTIFY_RUN_PERF=1 (set by `make test-fanotify-perf`).
// Requires: root, Linux >= 6.15, docker, fio, ext4 cache dir (Makefile
// sets TMPDIR).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/require"
)

// fanotifyPerfEnv holds paths, binaries, and process handles for one
// fanotify-vs-fuse performance run.
type fanotifyPerfEnv struct {
	nydusBin    string
	nydusifyBin string
	sourceImage string // remote OCI ref to pull and convert

	registry string
	repo     string
	tag      string
	imageRef string // local registry ref

	workDir    string
	checkDir   string
	bootstrap  string
	fuseConfig string
	fanConfig  string

	fuseMnt       string
	fuseCache     string
	fuseDaemonLog string
	fuseCmd       *exec.Cmd

	fanMnt       string
	fanCache     string
	fanLogDir    string
	fanDaemonLog string
	fanCmd       *exec.Cmd
	fanExited    chan struct{}

	fioTargetRel string // relative path within mount
	statRel      string
	readdirRel   string
	xattrRel     string // relative path to dir with most xattr-bearing files
	xattrName    string // most common xattr name (for getxattr benchmark)

	registryCID string
}

func TestFanotifyPerf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}
	if os.Getenv("FANOTIFY_RUN_PERF") == "" {
		t.Skip("set FANOTIFY_RUN_PERF=1 to enable")
	}
	if maj, min := kernelVersion(t); maj < 6 || (maj == 6 && min < 15) {
		t.Skipf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", maj, min)
	}

	sourceImage := os.Getenv("FANOTIFY_PERF_SOURCE_IMAGE")
	if sourceImage == "" {
		t.Skip("set FANOTIFY_PERF_SOURCE_IMAGE=<oci-ref> to enable (e.g. docker.io/library/openclaw:latest)")
	}

	fioBin := mustLookupFio(t)
	nydusBin := mustLookupExecutable(t, "nydus")
	nydusifyBin := mustLookupExecutable(t, "nydusify")

	if out, err := exec.Command(nydusBin, "fanotify", "--help").CombinedOutput(); err != nil {
		t.Skipf("nydus binary lacks the fanotify subcommand; build with --features cli,fanotify: %s", out)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker required for the throwaway local registry")
	}

	e := &fanotifyPerfEnv{
		nydusBin:    nydusBin,
		nydusifyBin: nydusifyBin,
		sourceImage: sourceImage,
		registry:    envOr("FANOTIFY_REGISTRY", "127.0.0.1:5000"),
		repo:        envOr("FANOTIFY_PERF_REPO", "fanotify-perf/openclaw"),
		tag:         envOr("FANOTIFY_PERF_TAG", "v1"),
	}
	e.imageRef = fmt.Sprintf("%s/%s:%s", e.registry, e.repo, e.tag)

	// Use a short work directory path instead of t.TempDir(): the EROFS
	// mount encodes every blob device as a "device=<path>" option, and the
	// kernel's mount data is capped at PAGE_SIZE (4096). A large image like
	// openclaw has 29 blob devices, each with a 64-char sha256 in its cache
	// filename — a long t.TempDir() prefix pushes the total over 4096 and
	// the mount fails with EINVAL.
	tmpBase := os.Getenv("TMPDIR")
	if tmpBase == "" {
		tmpBase = "/tmp"
	}
	e.workDir = filepath.Join(tmpBase, fmt.Sprintf("fp%d", os.Getpid()))
	require.NoError(t, os.MkdirAll(e.workDir, 0755))
	t.Cleanup(func() { _ = os.RemoveAll(e.workDir) })

	e.checkDir = filepath.Join(e.workDir, "ck")
	e.fuseMnt = filepath.Join(e.workDir, "fm")
	e.fuseCache = filepath.Join(e.workDir, "uc")
	e.fuseConfig = filepath.Join(e.workDir, "uc.yaml")
	e.fuseDaemonLog = filepath.Join(e.workDir, "uc.log")
	e.fanMnt = filepath.Join(e.workDir, "pm")
	e.fanCache = filepath.Join(e.workDir, "c") // shortest possible: appears in every device= mount option
	e.fanConfig = filepath.Join(e.workDir, "c.yaml")
	e.fanLogDir = filepath.Join(e.workDir, "pl")
	e.fanDaemonLog = filepath.Join(e.workDir, "c.log")
	e.bootstrap = filepath.Join(e.checkDir, "target", "bootstrap", "image", "image.boot")

	for _, d := range []string{e.fuseMnt, e.fuseCache, e.fanMnt, e.fanCache, e.fanLogDir} {
		require.NoError(t, os.MkdirAll(d, 0755))
	}
	t.Cleanup(func() { e.cleanup(t) })

	// --- setup: registry + tag/push source + convert + export bootstrap ---
	e.startLocalRegistry(t)
	e.prepareSourceImage(t)
	e.convertImage(t)
	e.writeConfigs(t)

	// --- FUSE phase ---
	t.Log("=== FUSE ===")
	fuseMountSec, fuseFirstReadSec := e.startFuseDaemon(t)
	e.discoverTargets(t, e.fuseMnt)
	fuseTarget, fuseStatDir, fuseReaddirDir := e.targetsFor(e.fuseMnt)
	fuseXattrDir := e.xattrDirFor(e.fuseMnt)
	e.prewarmCache(t, fuseTarget)
	e.warmupPageCache(t, fioBin, fuseTarget) // fully warm page cache
	fuseWarm := runBenchmarks(t, fioBin, fuseTarget, fuseStatDir, fuseReaddirDir, false)
	addMetaBenchmarks(t, fuseWarm, fuseXattrDir, e.xattrName, fuseStatDir)
	fuseDataFetched := cacheDirUsedBytes(e.fuseCache)
	dropCaches(t) // cold page cache, warm nydus cache
	fuseColdPage := runBenchmarks(t, fioBin, fuseTarget, fuseStatDir, fuseReaddirDir, true)
	addMetaBenchmarks(t, fuseColdPage, fuseXattrDir, e.xattrName, fuseStatDir)
	e.stopFuseDaemon(t)

	// --- fanotify phase ---
	t.Log("=== Fanotify ===")
	fanMountSec, fanFirstReadSec := e.startFanotifyDaemon(t)
	fanTarget, fanStatDir, fanReaddirDir := e.targetsFor(e.fanMnt)
	fanXattrDir := e.xattrDirFor(e.fanMnt)
	e.prewarmCache(t, fanTarget)
	e.warmupPageCache(t, fioBin, fanTarget)
	fanWarm := runBenchmarks(t, fioBin, fanTarget, fanStatDir, fanReaddirDir, false)
	addMetaBenchmarks(t, fanWarm, fanXattrDir, e.xattrName, fanStatDir)
	fanDataFetched := cacheDirUsedBytes(e.fanCache)
	dropCaches(t)
	fanColdPage := runBenchmarks(t, fioBin, fanTarget, fanStatDir, fanReaddirDir, true)
	addMetaBenchmarks(t, fanColdPage, fanXattrDir, e.xattrName, fanStatDir)

	e.stopFanotifyDaemon(t)

	printFanotifyPerfTable(t, fanColdPage, fanWarm, fuseColdPage, fuseWarm,
		fanMountSec, fanFirstReadSec, fuseMountSec, fuseFirstReadSec,
		fanDataFetched, fuseDataFetched)
}

// ------------------------------------------------------------------ setup ----

func (e *fanotifyPerfEnv) startLocalRegistry(t *testing.T) {
	t.Helper()
	host := e.registry
	if !e.registryIsLoopback() {
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
	require.Eventually(t, func() bool { return registryReady(host) }, 30*time.Second, time.Second, "local registry did not become ready")
	t.Log("  registry up")
}

// prepareSourceImage tags and pushes the source image into the local registry
// so nydusify can convert it via plain HTTP. If the source already points to
// our loopback registry, it's left as-is. This avoids nydusify pulling from a
// remote registry — the user pre-pulls via `docker pull` and the test handles
// the rest.
func (e *fanotifyPerfEnv) prepareSourceImage(t *testing.T) {
	t.Helper()
	if !e.registryIsLoopback() {
		return // external registry: nydusify convert pulls directly
	}
	// Already pointing at our registry?
	if strings.HasPrefix(e.sourceImage, e.registry+"/") {
		return
	}
	// Ensure the source image is available locally before tagging.
	t.Logf("docker pull %s", e.sourceImage)
	out, err := exec.Command("docker", "pull", e.sourceImage).CombinedOutput()
	require.NoError(t, err, "docker pull failed (is the image public?): %s", out)

	localRef := e.registry + "/" + e.sourceImage
	t.Logf("docker tag %s -> %s", e.sourceImage, localRef)
	out, err = exec.Command("docker", "tag", e.sourceImage, localRef).CombinedOutput()
	require.NoError(t, err, "docker tag failed: %s", out)
	t.Logf("docker push %s", localRef)
	out, err = exec.Command("docker", "push", localRef).CombinedOutput()
	require.NoError(t, err, "docker push failed: %s", out)
	e.sourceImage = localRef
	t.Log("  source image pushed to local registry")
}

func (e *fanotifyPerfEnv) convertImage(t *testing.T) {
	t.Helper()
	var insecure []string
	if e.registryIsLoopback() {
		insecure = []string{"--target-insecure", "--target-plain-http"}
		// If the source is now on our loopback registry, use plain HTTP for it too.
		if strings.HasPrefix(e.sourceImage, e.registry+"/") {
			insecure = append(insecure, "--source-insecure", "--source-plain-http")
		}
	}
	t.Logf("nydusify convert %s -> %s", e.sourceImage, e.imageRef)
	args := append([]string{"convert",
		"--source", e.sourceImage,
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

func (e *fanotifyPerfEnv) writeConfigs(t *testing.T) {
	t.Helper()
	insecure, skip := "false", "false"
	if e.registryIsLoopback() {
		insecure, skip = "true", "true"
	}
	tmpl := func(cacheDir, configPath string) {
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
`, e.registry, e.repo, insecure, skip, cacheDir)
		require.NoError(t, os.WriteFile(configPath, []byte(config), 0644))
	}
	tmpl(e.fuseCache, e.fuseConfig)
	tmpl(e.fanCache, e.fanConfig)
	t.Logf("  wrote configs (insecure=%s)", insecure)
}

// prewarmCache reads the entire fio target file to populate the nydus cache
// (blob cache files on disk + groupmap) for the bytes fio will touch. After
// this, all target-file reads hit the groupmap and never touch the registry
// — isolating the kernel read path (fanotify ext4) from the userspace read
// path (FUSE daemon).
//
// Only the fio target, not the whole tree: fio measures one file, so warming
// just that file keeps the WARM columns honest — they measure the steady
// fanotify overhead (event round trip while the blob is still marked), not a
// synthetic all-blobs-hot best case.
func (e *fanotifyPerfEnv) prewarmCache(t *testing.T, target string) {
	t.Helper()
	t.Logf("  prewarming nydus cache: %s", filepath.Base(target))
	n := readWhole(t, target)
	t.Logf("  prewarm done: %.1f MiB cached", float64(n)/(1<<20))
}

// warmupPageCache runs a short sequential read to fill the kernel page cache
// for the target file. Called after prewarmCache and before the WARM
// benchmarks so that the WARM run starts with fully warm page cache (not
// dependent on residual warmth from a prior COLD run).
func (e *fanotifyPerfEnv) warmupPageCache(t *testing.T, fioBin, target string) {
	t.Helper()
	t.Log("  warming page cache (seq read 10s)")
	out, err := exec.Command(fioBin, "--name=warmup", "--filename="+target,
		"--rw=read", "--bs=128k", "--direct=0", "--numjobs=1",
		"--runtime=10", "--time_based", "--readonly").CombinedOutput()
	require.NoError(t, err, "warmup fio failed: %s", out)
	t.Log("  page cache warm")
}

// --------------------------------------------------------------- daemon -----

// startFuseDaemon wipes the FUSE cache, drops page cache, and starts
// `nydus fuse` with the registry backend config. Returns mount-ready time
// and first-1MiB-read time (cold-start metrics).
func (e *fanotifyPerfEnv) startFuseDaemon(t *testing.T) (mountSec, firstReadSec float64) {
	t.Helper()
	wipeCacheDir(e.fuseCache)
	dropCaches(t)

	logFile, err := os.Create(e.fuseDaemonLog)
	require.NoError(t, err)
	start := time.Now()
	cmd := exec.Command(e.nydusBin, "fuse",
		"--bootstrap", e.bootstrap,
		"--config", e.fuseConfig,
		"--mountpoint", e.fuseMnt,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	e.fuseCmd = cmd
	_ = logFile.Close()

	require.Eventually(t, func() bool {
		return isMountpoint(e.fuseMnt)
	}, 60*time.Second, time.Second, "fuse daemon did not mount:\n%s", e.readFuseLog())
	mountSec = time.Since(start).Seconds()
	t.Logf("  fuse daemon ready (pid=%d, %.2fs)", cmd.Process.Pid, mountSec)

	// First cold read: 1 MiB from offset 0 to trigger registry fetch.
	targetHint := e.findLargestFile(t, e.fuseMnt)
	require.NotEmpty(t, targetHint, "no large file found in mount for cold-read timing")
	readStart := time.Now()
	_, err = readSlice(targetHint, 0, 1)
	require.NoError(t, err, "first cold read failed")
	firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.2fs", firstReadSec)
	return mountSec, firstReadSec
}

func (e *fanotifyPerfEnv) stopFuseDaemon(t *testing.T) {
	t.Helper()
	if e.fuseCmd == nil || e.fuseCmd.Process == nil {
		return
	}
	_ = e.fuseCmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = e.fuseCmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = e.fuseCmd.Process.Kill()
		<-done
	}
	e.fuseCmd = nil
	if isMountpoint(e.fuseMnt) {
		_ = exec.Command("fusermount", "-u", e.fuseMnt).Run()
		_ = exec.Command("umount", "-l", e.fuseMnt).Run()
	}
}

// startFanotifyDaemon wipes the fanotify cache, drops page cache, and starts
// `nydus fanotify` with the registry backend config. Returns mount-ready
// time and first-1MiB-read time.
func (e *fanotifyPerfEnv) startFanotifyDaemon(t *testing.T) (mountSec, firstReadSec float64) {
	t.Helper()
	wipeCacheDir(e.fanCache)
	dropCaches(t)

	logFile, err := os.Create(e.fanDaemonLog)
	require.NoError(t, err)
	start := time.Now()
	cmd := exec.Command(e.nydusBin, "fanotify",
		"--bootstrap", e.bootstrap,
		"--config", e.fanConfig,
		"--mountpoint", e.fanMnt,
		"--log-level", "info",
		"--log-dir", e.fanLogDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	e.fanCmd = cmd
	e.fanExited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(e.fanExited) }()
	_ = logFile.Close()

	require.Eventually(t, func() bool {
		select {
		case <-e.fanExited:
			require.FailNowf(t, "fanotify daemon exited during startup", "%s", e.readFanLog())
		default:
		}
		return isMountpoint(e.fanMnt) && e.countFanLogs(`event loop ready`) > 0
	}, 60*time.Second, time.Second, "fanotify daemon did not mount:\n%s", e.readFanLog())
	mountSec = time.Since(start).Seconds()
	t.Logf("  fanotify daemon ready (pid=%d, %.2fs)", cmd.Process.Pid, mountSec)

	// First cold read.
	targetHint := e.findLargestFile(t, e.fanMnt)
	require.NotEmpty(t, targetHint, "no large file found in mount for cold-read timing")
	readStart := time.Now()
	_, err = readSlice(targetHint, 0, 1)
	require.NoError(t, err, "first cold read failed")
	firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.2fs", firstReadSec)
	return mountSec, firstReadSec
}

func (e *fanotifyPerfEnv) stopFanotifyDaemon(t *testing.T) {
	t.Helper()
	if e.fanCmd == nil || e.fanCmd.Process == nil {
		return
	}
	if e.fanExited != nil {
		select {
		case <-e.fanExited:
			e.fanCmd = nil
			return
		default:
		}
	}
	_ = e.fanCmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.fanExited:
	case <-time.After(20 * time.Second):
		_ = e.fanCmd.Process.Kill()
		<-e.fanExited
	}
	e.fanCmd = nil
	if isMountpoint(e.fanMnt) {
		_ = exec.Command("umount", e.fanMnt).Run()
		_ = exec.Command("umount", "-l", e.fanMnt).Run()
	}
}

// ----------------------------------------------------------- discovery ------

// discoverTargets walks the mount (stat only — metadata path, no backend
// fetch) and selects the largest regular file for fio, the directory with
// the most files for stat, and the directory with the most subdirs for
// readdir. Called once after the first daemon mounts; both daemons serve
// the same image so the tree is identical.
// discoverTargets walks the mount (stat only — metadata path, no backend
// fetch) and stores RELATIVE paths for fio target, stat dir, and readdir dir.
// Both daemons serve the same image, so the relative paths are valid under
// either mountpoint — resolved by targetsFor() per phase.
func (e *fanotifyPerfEnv) discoverTargets(t *testing.T, mnt string) {
	t.Helper()
	target := e.findLargestFile(t, mnt)
	require.NotEmpty(t, target, "no regular file found for fio target")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	require.Greater(t, fi.Size(), int64(4<<20), "fio target file too small (< 4 MiB)")
	rel, err := filepath.Rel(mnt, target)
	require.NoError(t, err)
	e.fioTargetRel = rel
	t.Logf("  fio target: %s (%.1f MiB)", target, float64(fi.Size())/(1<<20))

	statDir, readdirDir := e.findMetadataDirs(t, mnt)
	e.statRel, _ = filepath.Rel(mnt, statDir)
	e.readdirRel, _ = filepath.Rel(mnt, readdirDir)
	t.Logf("  stat dir: %s, readdir dir: %s", statDir, readdirDir)

	e.xattrRel, e.xattrName = findXattrTargets(t, mnt)
	if e.xattrRel != "" {
		// findXattrTargets returns an absolute path; convert to mount-relative
		// so xattrDirFor() can join it correctly against either mountpoint.
		if rel, err := filepath.Rel(mnt, e.xattrRel); err == nil {
			e.xattrRel = rel
		}
		t.Logf("  xattr dir: %s (getxattr key: %s)", filepath.Join(mnt, e.xattrRel), e.xattrName)
	} else {
		t.Log("  xattr dir: none found (listxattr/getxattr will be skipped)")
	}
}

// targetsFor resolves the stored relative paths against the given mountpoint.
func (e *fanotifyPerfEnv) targetsFor(mnt string) (fioTarget, statDir, readdirDir string) {
	return filepath.Join(mnt, e.fioTargetRel),
		filepath.Join(mnt, e.statRel),
		filepath.Join(mnt, e.readdirRel)
}

// xattrDirFor resolves the stored xattr relative path against the given mountpoint.
func (e *fanotifyPerfEnv) xattrDirFor(mnt string) string {
	if e.xattrRel == "" {
		return ""
	}
	return filepath.Join(mnt, e.xattrRel)
}

func (e *fanotifyPerfEnv) findLargestFile(t *testing.T, mnt string) string {
	t.Helper()
	var best string
	var bestSize int64
	_ = filepath.Walk(mnt, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > bestSize {
			best, bestSize = path, info.Size()
		}
		return nil
	})
	return best
}

func (e *fanotifyPerfEnv) findMetadataDirs(t *testing.T, mnt string) (statDir, readdirDir string) {
	t.Helper()
	var statBest, readdirBest int
	_ = filepath.Walk(mnt, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		entries, _ := os.ReadDir(path)
		fileCount, subDirCount := 0, 0
		for _, ent := range entries {
			if ent.IsDir() {
				subDirCount++
			} else {
				fileCount++
			}
		}
		if fileCount > statBest {
			statBest, statDir = fileCount, path
		}
		if subDirCount > readdirBest {
			readdirBest, readdirDir = subDirCount, path
		}
		return nil
	})
	if statDir == "" {
		statDir = mnt
	}
	if readdirDir == "" {
		readdirDir = mnt
	}
	return statDir, readdirDir
}

// -------------------------------------------------------------- helpers -----

func (e *fanotifyPerfEnv) registryIsLoopback() bool {
	return strings.HasPrefix(e.registry, "127.0.0.1:") ||
		strings.HasPrefix(e.registry, "localhost:") ||
		strings.HasPrefix(e.registry, "[::1]:")
}

func (e *fanotifyPerfEnv) readFuseLog() string {
	data, _ := os.ReadFile(e.fuseDaemonLog)
	return string(data)
}

func (e *fanotifyPerfEnv) readFanLog() string {
	var b strings.Builder
	if data, err := os.ReadFile(e.fanDaemonLog); err == nil {
		b.Write(data)
	}
	entries, _ := os.ReadDir(e.fanLogDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			if data, err := os.ReadFile(filepath.Join(e.fanLogDir, entry.Name())); err == nil {
				b.Write(data)
			}
		}
	}
	return b.String()
}

func (e *fanotifyPerfEnv) countFanLogs(pattern string) int {
	re := regexp.MustCompile(pattern)
	count := 0
	for _, line := range strings.Split(e.readFanLog(), "\n") {
		if re.MatchString(line) {
			count++
		}
	}
	return count
}

func wipeCacheDir(cacheDir string) {
	for _, pattern := range []string{"*.blob.data", "*.blob.meta", "*.group.map", "*.prefetch.lock"} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, pattern))
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}

func cacheDirUsedBytes(cacheDir string) float64 {
	var total int64
	matches, _ := filepath.Glob(filepath.Join(cacheDir, "*.blob.data"))
	for _, m := range matches {
		total += usedBytes(m)
	}
	return float64(total) / (1024 * 1024)
}

func (e *fanotifyPerfEnv) cleanup(t *testing.T) {
	e.stopFuseDaemon(t)
	e.stopFanotifyDaemon(t)
	if e.registryCID != "" {
		_ = exec.Command("docker", "rm", "-f", e.registryCID).Run()
	}
}

// --------------------------------------------------------------- output -----

func printFanotifyPerfTable(
	t *testing.T,
	fanColdPage, fanWarm, fuseColdPage, fuseWarm map[string]*benchResult,
	fanMountSec, fanFirstReadSec, fuseMountSec, fuseFirstReadSec float64,
	fanDataFetched, fuseDataFetched float64,
) {
	type row struct {
		label string
		key   string
		unit  string
		get   func(r *benchResult) float64
	}

	bw := func(r *benchResult) float64 { return r.ReadBW }
	iops := func(r *benchResult) float64 { return r.ReadIOPS }
	lat := func(r *benchResult) float64 { return r.ReadLat }

	fmtCell := func(m map[string]*benchResult, key string, get func(r *benchResult) float64, unit string) string {
		if r, ok := m[key]; ok && r != nil {
			return fmt.Sprintf("%.1f %s", get(r), unit)
		}
		return "—"
	}

	rows := []row{
		{"Seq Read BW (128K)", "seq_read_128k", "MiB/s", bw},
		{"Rand Read BW (128K)", "rand_read_128k", "MiB/s", bw},
		{"Rand Read IOPS (4K)", "rand_read_4k", "IOPS", iops},
		{"Rand Read Lat (4K)", "rand_read_4k", "µs", lat},
		{"Seq 4t BW (128K)", "seq_read_4t_128k", "MiB/s", bw},
		{"Rand 4t BW (128K)", "rand_read_4t_128k", "MiB/s", bw},
		{"Stat IOPS", "stat", "IOPS", iops},
		{"Stat Latency", "stat", "µs", lat},
		{"Readdir IOPS", "readdir", "IOPS", iops},
		{"Readdir Latency", "readdir", "µs", lat},
		{"Listxattr IOPS", "listxattr", "IOPS", iops},
		{"Listxattr Latency", "listxattr", "µs", lat},
		{"Getxattr IOPS", "getxattr", "IOPS", iops},
		{"Getxattr Latency", "getxattr", "µs", lat},
		{"Readdir+Stat IOPS", "readdir_stat", "IOPS", iops},
		{"Readdir+Stat Latency", "readdir_stat", "µs", lat},
	}

	// cold-page = warm nydus cache + cold page cache (dropCaches before each job)
	// warm      = warm nydus cache + warm page cache (no dropCaches)
	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.Style().Options.SeparateRows = false
	tw.AppendHeader(table.Row{"Benchmark", "fanotify warm", "fanotify cold-page", "fuse warm", "fuse cold-page"})
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Align: text.AlignLeft},
		{Number: 2, Align: text.AlignRight},
		{Number: 3, Align: text.AlignRight},
		{Number: 4, Align: text.AlignRight},
		{Number: 5, Align: text.AlignRight},
	})

	for _, r := range rows {
		tw.AppendRow(table.Row{
			r.label,
			fmtCell(fanWarm, r.key, r.get, r.unit),
			fmtCell(fanColdPage, r.key, r.get, r.unit),
			fmtCell(fuseWarm, r.key, r.get, r.unit),
			fmtCell(fuseColdPage, r.key, r.get, r.unit),
		})
	}

	tw.AppendSeparator()
	tw.AppendRow(table.Row{
		"Mount ready time",
		"—", fmt.Sprintf("%.2f s", fanMountSec),
		"—", fmt.Sprintf("%.2f s", fuseMountSec),
	})
	tw.AppendRow(table.Row{
		"First 1MiB read time",
		"—", fmt.Sprintf("%.2f s", fanFirstReadSec),
		"—", fmt.Sprintf("%.2f s", fuseFirstReadSec),
	})

	tw.AppendSeparator()
	tw.AppendRow(table.Row{
		"Data fetched (prewarm)",
		"—", fmt.Sprintf("%.1f MiB", fanDataFetched),
		"—", fmt.Sprintf("%.1f MiB", fuseDataFetched),
	})

	t.Log("\nFanotify vs FUSE Performance Comparison (registry backend)\n" + tw.Render())
}
