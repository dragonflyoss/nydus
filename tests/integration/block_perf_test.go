package integration

// FUSE vs NBD vs ublk performance comparison (local backend).
//
// All three modes serve the SAME image (bootstrap + blob dir, prefetch
// disabled, separate cache dirs), so the comparison isolates the read
// transport:
//
//	FUSE:  page-cache miss -> FUSE request -> daemon groupmap check + pread
//	      cache file -> FUSE reply. The page cache sits at the FUSE file
//	      level; every metadata call (stat/readdir) is a userspace round
//	      trip.
//	NBD:   page-cache miss -> EROFS -> block layer -> NBD socket -> daemon
//	      pread cache file -> reply. The page cache sits above the block
//	      device; warm hits never reach the daemon, and metadata is served
//	      by the kernel EROFS driver from cached bootstrap blocks.
//	ublk:  page-cache miss -> EROFS -> ublk_drv -> userspace io_uring ->
//	      daemon pread cache file -> reply. Like NBD the page cache sits
//	      above the block device and metadata is served by kernel EROFS;
//	      the difference vs NBD is the transport — ublk_drv routes block
//	      requests through io_uring SQE/CQE pairs in shared memory rather
//	      than a kernel socket, and each hardware queue is served by its
//	      own userspace thread.
//
// Methodology (per mode):
//
//  1. cold start: wipe cache + dropCaches, start the daemon; record
//     mount-ready time, first-1MiB read latency, and the full-file cold
//     prewarm throughput (the on-demand fetch path, end to end).
//  2. warmup page cache: short seq read -> fully warm.
//  3. WARM suite (no dropCaches): steady-state, all modes should serve
//     from page cache. Daemon CPU is sampled around the suite — the NBD
//     and ublk daemons should burn ~zero here, the FUSE daemon pays per
//     call.
//  4. COLD-PAGE suite (dropCaches before each fio job): warm nydus cache,
//     cold page cache — the headline transport comparison (NBD socket +
//     block layer, ublk io_uring + block layer, vs FUSE request/reply),
//     all daemons serving pread from the same local cache-file bytes.
//  5. O_DIRECT jobs: bypass the page cache on every request in all modes —
//     the purest per-request round-trip measure, free of the "first pass
//     cold, later passes warm" mixing that time_based direct=0 jobs suffer
//     after dropCaches.
//
// Fairness notes: device readahead (/dev/nbdX, /dev/ublkbN, kernel default)
// and FUSE max_readahead are left at their defaults — that is what real
// deployments see — so sequential direct=0 numbers partly reflect readahead
// policy, not just protocol overhead; the direct=1 rows are the controlled
// comparison. The NBD worker count defaults to min(ncpu, 16) kernel
// connections; ublk defaults to min(ncpu, 4) hardware queues.
//
// Activation: BLOCK_RUN_PERF=1 (set by `make test-block-perf`). Requires
// root, the nbd and ublk_drv kernel modules, kernel EROFS support, and fio.
// Corpus and runtime knobs are shared with TestPerf (NYDUSFS_PERF_*).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/integration/texture"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/require"
)

// blockPerfEnv holds paths, binaries, and process handles for one
// FUSE-vs-NBD-vs-ublk performance run.
type blockPerfEnv struct {
	nydusBin string
	fioBin   string
	nbdDev   string // free /dev/nbdX picked for the NBD mode

	workDir   string
	blobDir   string
	bootstrap string

	fuseMnt    string
	fuseCache  string
	fuseConfig string
	fuseLog    string
	fuseCmd    *exec.Cmd

	nbdMnt    string
	nbdCache  string
	nbdConfig string
	nbdLogDir string
	nbdLog    string
	nbdCmd    *exec.Cmd
	nbdExited chan struct{}

	ublkMnt     string
	ublkCache   string
	ublkConfig  string
	ublkLogDir  string
	ublkLog     string
	ublkCmd     *exec.Cmd
	ublkExited  chan struct{}
	ublkDevPath string
}

// coldStart captures the per-mode cold-start metrics.
type coldStart struct {
	mountSec     float64
	firstReadSec float64
	prewarmMiBps float64
}

// modeResults collects every measurement for one serving mode.
type modeResults struct {
	warm, cold, direct map[string]*benchResult
	start              *coldStart
	warmCPU, coldCPU   float64
	fetched            float64
}

// modeDesc binds a serving mode's per-mode fields to the generic phase
// runner so FUSE/NBD/ublk are measured identically.
type modeDesc struct {
	name  string
	mnt   string
	cache string
	start func(t *testing.T, targetRel string) *coldStart
	stop  func(t *testing.T)
	pid   func() int
}

func TestBlockPerf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}
	if os.Getenv("BLOCK_RUN_PERF") == "" {
		t.Skip("set BLOCK_RUN_PERF=1 to enable")
	}
	if !erofsSupported() {
		t.Skip("erofs not in /proc/filesystems — kernel lacks EROFS support")
	}
	nbdDev, err := findFreeNbdDevice()
	if err != nil {
		t.Skipf("no free NBD device: %v (is the nbd module loaded? try: modprobe nbd)", err)
	}
	if !ublkAvailable() {
		t.Skip("ublk_drv unavailable (needs Linux 6.0+ and /dev/ublk-control; try: modprobe ublk_drv)")
	}

	fioBin := mustLookupFio(t)
	nydusBin := mustLookupExecutable(t, "nydus")
	for _, sub := range []string{"fuse", "nbd", "ublk"} {
		if out, err := exec.Command(nydusBin, sub, "--help").CombinedOutput(); err != nil {
			t.Skipf("nydus binary lacks the %s subcommand; build with --features cli,fuse,nbd,ublk: %s", sub, out)
		}
	}

	e := &blockPerfEnv{nydusBin: nydusBin, fioBin: fioBin, nbdDev: nbdDev}
	e.workDir = t.TempDir()
	corpusDir := filepath.Join(e.workDir, "corpus")
	e.blobDir = filepath.Join(e.workDir, "blobs")
	e.bootstrap = filepath.Join(e.workDir, "bootstrap.boot")
	e.fuseMnt = filepath.Join(e.workDir, "fuse-mnt")
	e.fuseCache = filepath.Join(e.workDir, "fuse-cache")
	e.fuseConfig = filepath.Join(e.workDir, "fuse.yaml")
	e.fuseLog = filepath.Join(e.workDir, "fuse.log")
	e.nbdMnt = filepath.Join(e.workDir, "nbd-mnt")
	e.nbdCache = filepath.Join(e.workDir, "nbd-cache")
	e.nbdConfig = filepath.Join(e.workDir, "nbd.yaml")
	e.nbdLogDir = filepath.Join(e.workDir, "nbd-logs")
	e.nbdLog = filepath.Join(e.workDir, "nbd.log")
	e.ublkMnt = filepath.Join(e.workDir, "ublk-mnt")
	e.ublkCache = filepath.Join(e.workDir, "ublk-cache")
	e.ublkConfig = filepath.Join(e.workDir, "ublk.yaml")
	e.ublkLogDir = filepath.Join(e.workDir, "ublk-logs")
	e.ublkLog = filepath.Join(e.workDir, "ublk.log")
	for _, d := range []string{e.fuseMnt, e.fuseCache, e.nbdMnt, e.nbdCache, e.nbdLogDir, e.ublkMnt, e.ublkCache, e.ublkLogDir} {
		require.NoError(t, os.MkdirAll(d, 0755))
	}
	t.Cleanup(func() { e.cleanup(t) })

	t.Log("Generating performance corpus...")
	texture.MakePerfCorpus(t, corpusDir)
	t.Log("Building NydusFS image (chunksize=1MiB)...")
	buildNydusFSImageToDir(t, nydusBin, e.bootstrap, e.blobDir, corpusDir, 1024*1024)
	e.writeConfigs(t)

	// Fixed corpus layout, same paths as TestPerf.
	const targetRel, statRel, readdirRel = "large/file_0.bin", "small", "dirs"

	modes := []modeDesc{
		{"fuse", e.fuseMnt, e.fuseCache, e.startFuse, e.stopFuse, func() int { return e.fuseCmdPid() }},
		{"nbd", e.nbdMnt, e.nbdCache, e.startNbd, e.stopNbd, func() int { return e.nbdCmdPid() }},
		{"ublk", e.ublkMnt, e.ublkCache, e.startUblk, e.stopUblk, func() int { return e.ublkCmdPid() }},
	}

	results := make(map[string]*modeResults, len(modes))
	for _, m := range modes {
		t.Logf("=== %s ===", m.name)
		results[m.name] = e.runMode(t, m, targetRel, statRel, readdirRel)
	}

	printBlockPerfTable(t, modes, results)
}

// runMode runs the full per-mode benchmark suite: cold start + prewarm,
// warm suite, cold-page suite, and O_DIRECT jobs, sampling daemon CPU
// around each suite.
func (e *blockPerfEnv) runMode(t *testing.T, m modeDesc, targetRel, statRel, readdirRel string) *modeResults {
	t.Helper()
	res := &modeResults{start: m.start(t, targetRel)}
	target := filepath.Join(m.mnt, targetRel)
	statDir := filepath.Join(m.mnt, statRel)
	readdirDir := filepath.Join(m.mnt, readdirRel)

	res.start.prewarmMiBps = e.prewarm(t, target)
	e.warmupPageCache(t, target)

	cpu0 := processCPUSeconds(m.pid())
	res.warm = runBenchmarks(t, e.fioBin, target, statDir, readdirDir, false)
	res.warmCPU = processCPUSeconds(m.pid()) - cpu0
	res.fetched = cacheDirUsedBytes(m.cache)

	dropCaches(t)
	cpu0 = processCPUSeconds(m.pid())
	res.cold = runBenchmarks(t, e.fioBin, target, statDir, readdirDir, true)
	res.coldCPU = processCPUSeconds(m.pid()) - cpu0

	res.direct = e.runDirectJobs(t, target)
	m.stop(t)
	return res
}

// ------------------------------------------------------------------ setup ----

// writeConfigs writes one local-backend storage config per mode: shared blob
// dir, separate cache dirs. Prefetch stays disabled — a background prefetch
// would warm the cache mid-run and corrupt the cold measurements.
func (e *blockPerfEnv) writeConfigs(t *testing.T) {
	t.Helper()
	tmpl := func(cacheDir, path string) {
		config := fmt.Sprintf(
			"backend:\n  type: local\n  config:\n    dir: %s\ncache:\n  type: local\n  config:\n    dir: %s\nprefetch:\n  enable: false\n",
			e.blobDir, cacheDir,
		)
		require.NoError(t, os.WriteFile(path, []byte(config), 0644))
	}
	tmpl(e.fuseCache, e.fuseConfig)
	tmpl(e.nbdCache, e.nbdConfig)
	tmpl(e.ublkCache, e.ublkConfig)
	t.Log("  wrote configs (local backend, prefetch disabled)")
}

// ----------------------------------------------------------------- daemons ----

func (e *blockPerfEnv) fuseCmdPid() int {
	if e.fuseCmd != nil && e.fuseCmd.Process != nil {
		return e.fuseCmd.Process.Pid
	}
	return 0
}
func (e *blockPerfEnv) nbdCmdPid() int {
	if e.nbdCmd != nil && e.nbdCmd.Process != nil {
		return e.nbdCmd.Process.Pid
	}
	return 0
}
func (e *blockPerfEnv) ublkCmdPid() int {
	if e.ublkCmd != nil && e.ublkCmd.Process != nil {
		return e.ublkCmd.Process.Pid
	}
	return 0
}

// startFuse wipes the FUSE cache, drops the page cache, and starts
// `nydus fuse`. Returns mount-ready time and first-1MiB cold-read time.
func (e *blockPerfEnv) startFuse(t *testing.T, targetRel string) *coldStart {
	t.Helper()
	wipeCacheDir(e.fuseCache)
	dropCaches(t)

	logFile, err := os.Create(e.fuseLog)
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
	}, 60*time.Second, 200*time.Millisecond, "fuse daemon did not mount:\n%s", mustReadFile(e.fuseLog))
	cs := &coldStart{mountSec: time.Since(start).Seconds()}
	t.Logf("  fuse daemon ready (pid=%d, %.2fs)", cmd.Process.Pid, cs.mountSec)

	readStart := time.Now()
	_, err = readSlice(filepath.Join(e.fuseMnt, targetRel), 0, 1)
	require.NoError(t, err, "first cold read failed")
	cs.firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.3fs", cs.firstReadSec)
	return cs
}

func (e *blockPerfEnv) stopFuse(t *testing.T) {
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

// startNbd wipes the NBD cache, drops the page cache, and starts `nydus nbd`
// with a mountpoint. Log level stays at the default info so the daemon does
// not pay per-fetch debug logging the FUSE daemon is not paying.
func (e *blockPerfEnv) startNbd(t *testing.T, targetRel string) *coldStart {
	t.Helper()
	wipeCacheDir(e.nbdCache)
	dropCaches(t)

	logFile, err := os.Create(e.nbdLog)
	require.NoError(t, err)
	start := time.Now()
	cmd := exec.Command(e.nydusBin, "nbd",
		"--bootstrap", e.bootstrap,
		"--config", e.nbdConfig,
		"--device", e.nbdDev,
		"--mountpoint", e.nbdMnt,
		"--log-level", "info",
		"--log-dir", e.nbdLogDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	e.nbdCmd = cmd
	e.nbdExited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(e.nbdExited) }()
	_ = logFile.Close()

	require.Eventually(t, func() bool {
		select {
		case <-e.nbdExited:
			require.FailNowf(t, "nbd daemon exited during startup", "%s", mustReadFile(e.nbdLog))
		default:
		}
		return isMountpoint(e.nbdMnt)
	}, 60*time.Second, 200*time.Millisecond, "nbd daemon did not mount:\n%s", mustReadFile(e.nbdLog))
	cs := &coldStart{mountSec: time.Since(start).Seconds()}
	t.Logf("  nbd daemon ready (pid=%d, device=%s, %.2fs)", cmd.Process.Pid, e.nbdDev, cs.mountSec)

	readStart := time.Now()
	_, err = readSlice(filepath.Join(e.nbdMnt, targetRel), 0, 1)
	require.NoError(t, err, "first cold read failed")
	cs.firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.3fs", cs.firstReadSec)
	return cs
}

func (e *blockPerfEnv) stopNbd(t *testing.T) {
	t.Helper()
	if e.nbdCmd == nil || e.nbdCmd.Process == nil {
		return
	}
	if e.nbdExited != nil {
		select {
		case <-e.nbdExited:
			e.nbdCmd = nil
			return
		default:
		}
	}
	_ = e.nbdCmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.nbdExited:
	case <-time.After(20 * time.Second):
		_ = e.nbdCmd.Process.Kill()
		<-e.nbdExited
	}
	e.nbdCmd = nil
	if isMountpoint(e.nbdMnt) {
		_ = exec.Command("umount", e.nbdMnt).Run()
		_ = exec.Command("umount", "-l", e.nbdMnt).Run()
	}
	waitNbdDeviceRelease(t, e.nbdDev)
}

// startUblk wipes the ublk cache, drops the page cache, starts `nydus ublk`
// and mounts the resulting /dev/ublkbN as EROFS. The daemon prints the
// device path on stdout; stdout is tee'd to the log file so the line is
// preserved alongside any stderr output. Log level stays at info to match
// the NBD daemon.
func (e *blockPerfEnv) startUblk(t *testing.T, targetRel string) *coldStart {
	t.Helper()
	wipeCacheDir(e.ublkCache)
	dropCaches(t)

	logFile, err := os.Create(e.ublkLog)
	require.NoError(t, err)
	start := time.Now()
	cmd := exec.Command(e.nydusBin, "ublk",
		"--bootstrap", e.bootstrap,
		"--config", e.ublkConfig,
		"--log-level", "info",
		"--log-dir", e.ublkLogDir,
	)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	e.ublkCmd = cmd
	e.ublkExited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(e.ublkExited) }()

	// Scan stdout for the /dev/ublkbN line the daemon prints once ready;
	// tee every line into the log file so it is preserved. The daemon
	// prints exactly one line then idles, so a blocked write is not a
	// concern; the scanner drains to EOF on daemon exit.
	go func() {
		s := bufio.NewScanner(stdoutPipe)
		for s.Scan() {
			line := s.Text()
			_, _ = logFile.WriteString(line + "\n")
			t := strings.TrimSpace(line)
			if e.ublkDevPath == "" && strings.HasPrefix(t, "/dev/ublkb") {
				e.ublkDevPath = t
			}
		}
	}()

	require.Eventually(t, func() bool {
		select {
		case <-e.ublkExited:
			require.FailNowf(t, "ublk daemon exited during startup", "%s", mustReadFile(e.ublkLog))
		default:
		}
		return e.ublkDevPath != ""
	}, 60*time.Second, 200*time.Millisecond, "ublk daemon did not report a device path:\n%s", mustReadFile(e.ublkLog))
	require.NotEmpty(t, e.ublkDevPath, "ublk dev path not captured")
	require.Eventually(t, func() bool {
		_, err := os.Stat(e.ublkDevPath)
		return err == nil
	}, 10*time.Second, 200*time.Millisecond, "%s did not appear", e.ublkDevPath)

	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", e.ublkDevPath, e.ublkMnt).CombinedOutput()
	require.NoError(t, err, "failed to mount %s as erofs: %s", e.ublkDevPath, out)
	cs := &coldStart{mountSec: time.Since(start).Seconds()}
	t.Logf("  ublk daemon ready (pid=%d, device=%s, %.2fs)", cmd.Process.Pid, e.ublkDevPath, cs.mountSec)

	readStart := time.Now()
	_, err = readSlice(filepath.Join(e.ublkMnt, targetRel), 0, 1)
	require.NoError(t, err, "first cold read failed")
	cs.firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.3fs", cs.firstReadSec)
	return cs
}

func (e *blockPerfEnv) stopUblk(t *testing.T) {
	t.Helper()
	// Unmount BEFORE stopping the daemon: the daemon serves I/O for its own
	// block device, so an unmount that flushes I/O while the daemon is
	// exiting would deadlock (same hazard documented in ublk_test.go).
	if isMountpoint(e.ublkMnt) {
		_ = exec.Command("umount", e.ublkMnt).Run()
		_ = exec.Command("umount", "-l", e.ublkMnt).Run()
	}
	if e.ublkCmd == nil || e.ublkCmd.Process == nil {
		return
	}
	if e.ublkExited != nil {
		select {
		case <-e.ublkExited:
			e.ublkCmd = nil
			e.ublkDevPath = ""
			return
		default:
		}
	}
	_ = e.ublkCmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.ublkExited:
	case <-time.After(20 * time.Second):
		_ = e.ublkCmd.Process.Kill()
		<-e.ublkExited
	}
	e.ublkCmd = nil
	e.ublkDevPath = ""
}

func (e *blockPerfEnv) cleanup(t *testing.T) {
	e.stopUblk(t)
	e.stopNbd(t)
	e.stopFuse(t)
}

// ----------------------------------------------------------------- phases ----

// prewarm cold-reads the entire fio target, filling the nydus cache and
// groupmap for every byte fio will touch, and returns the achieved
// throughput — this IS the end-to-end on-demand fetch path measurement.
func (e *blockPerfEnv) prewarm(t *testing.T, target string) float64 {
	t.Helper()
	start := time.Now()
	n := readWhole(t, target)
	sec := time.Since(start).Seconds()
	mibps := float64(n) / (1 << 20) / sec
	t.Logf("  prewarm: %.1f MiB cold-read at %.1f MiB/s", float64(n)/(1<<20), mibps)
	return mibps
}

// warmupPageCache runs a short sequential read so the WARM suite starts with
// a fully warm page cache rather than residual warmth from the prewarm pass.
func (e *blockPerfEnv) warmupPageCache(t *testing.T, target string) {
	t.Helper()
	t.Log("  warming page cache (seq read 10s)")
	out, err := exec.Command(e.fioBin, "--name=warmup", "--filename="+target,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0", "--numjobs=1",
		"--runtime=10", "--time_based", "--readonly").CombinedOutput()
	require.NoError(t, err, "warmup fio failed: %s", out)
}

// runDirectJobs runs the O_DIRECT fio jobs. Tolerant of failure — O_DIRECT
// support through FUSE is not guaranteed on every kernel/daemon combination —
// a failed job is logged and its row omitted rather than failing the run.
func (e *blockPerfEnv) runDirectJobs(t *testing.T, target string) map[string]*benchResult {
	t.Helper()
	fioRuntime := texture.GetEnvAsInt("NYDUSFS_PERF_FIO_RUNTIME", 20)
	results := make(map[string]*benchResult)
	jobs := []struct {
		key  string
		args []string
	}{
		{"seq_read_128k_direct", []string{
			"--name=seq_read_128k_direct", "--filename=" + target,
			"--rw=read", "--bs=128k", "--direct=1",
			"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
		}},
		{"rand_read_4k_direct", []string{
			"--name=rand_read_4k_direct", "--filename=" + target,
			"--rw=randread", "--bs=4k", "--direct=1",
			"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
		}},
	}
	for _, j := range jobs {
		out, err := exec.Command(e.fioBin, append([]string{"--output-format=json"}, j.args...)...).CombinedOutput()
		if err != nil {
			t.Logf("  direct job %s failed (O_DIRECT unsupported here?): %v", j.key, err)
			continue
		}
		var parsed fioJSONResult
		if json.Unmarshal(out, &parsed) != nil || len(parsed.Jobs) == 0 {
			t.Logf("  direct job %s produced unparseable output", j.key)
			continue
		}
		job := parsed.Jobs[0]
		results[j.key] = &benchResult{
			Name:     job.Jobname,
			ReadBW:   job.Read.Bw / 1024,
			ReadIOPS: job.Read.Iops,
			ReadLat:  job.Read.LatNs.Mean / 1000,
		}
	}
	return results
}

// processCPUSeconds returns the user+system CPU seconds pid has consumed so
// far, from /proc/<pid>/stat (fields 14 and 15, USER_HZ = 100 on Linux).
// Returns 0 on any read/parse failure.
func processCPUSeconds(pid int) float64 {
	if pid <= 0 {
		return 0
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// comm (field 2) may contain spaces; parse from after the closing paren.
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[i+2:])
	// fields[0] is field 3 (state), so utime (14) and stime (15) are at
	// indexes 11 and 12.
	if len(fields) < 13 {
		return 0
	}
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	return (utime + stime) / 100.0
}

// ------------------------------------------------------------------ output ----

func printBlockPerfTable(t *testing.T, modes []modeDesc, results map[string]*modeResults) {
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
		{"Seq Read BW (4K)", "seq_read_4k", "MiB/s", bw},
		{"Rand Read IOPS (4K)", "rand_read_4k", "IOPS", iops},
		{"Rand Read Lat (4K)", "rand_read_4k", "µs", lat},
		{"Seq 4t BW (128K)", "seq_read_4t_128k", "MiB/s", bw},
		{"Rand 4t BW (128K)", "rand_read_4t_128k", "MiB/s", bw},
		{"Seq 4t BW (4K)", "seq_read_4t_4k", "MiB/s", bw},
		{"Rand 4t BW (4K)", "rand_read_4t_4k", "MiB/s", bw},
		{"Stat IOPS", "stat", "IOPS", iops},
		{"Stat Latency", "stat", "µs", lat},
		{"Readdir IOPS", "readdir", "IOPS", iops},
		{"Readdir Latency", "readdir", "µs", lat},
	}

	// warm       = warm nydus cache + warm page cache (no dropCaches)
	// cold-page  = warm nydus cache + cold page cache (dropCaches per job)
	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.Style().Options.SeparateRows = false
	header := table.Row{"Benchmark"}
	colCfg := []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}}
	for i := range modes {
		header = append(header, modes[i].name+" warm", modes[i].name+" cold-page")
		colCfg = append(colCfg,
			table.ColumnConfig{Number: 2 + 2*i, Align: text.AlignRight},
			table.ColumnConfig{Number: 3 + 2*i, Align: text.AlignRight},
		)
	}
	tw.AppendHeader(header)
	tw.SetColumnConfigs(colCfg)

	for _, r := range rows {
		cells := table.Row{r.label}
		for _, m := range modes {
			cells = append(cells,
				fmtCell(results[m.name].warm, r.key, r.get, r.unit),
				fmtCell(results[m.name].cold, r.key, r.get, r.unit),
			)
		}
		tw.AppendRow(cells)
	}

	// O_DIRECT rows bypass the page cache in all modes, so warm/cold-page
	// makes no difference; rendered once in the cold-page columns.
	tw.AppendSeparator()
	directRows := []row{
		{"Seq Direct BW (128K)", "seq_read_128k_direct", "MiB/s", bw},
		{"Rand Direct IOPS (4K)", "rand_read_4k_direct", "IOPS", iops},
		{"Rand Direct Lat (4K)", "rand_read_4k_direct", "µs", lat},
	}
	for _, r := range directRows {
		cells := table.Row{r.label}
		for _, m := range modes {
			cells = append(cells, "—", fmtCell(results[m.name].direct, r.key, r.get, r.unit))
		}
		tw.AppendRow(cells)
	}

	tw.AppendSeparator()
	{
		cells := table.Row{"Daemon CPU (suite)"}
		for _, m := range modes {
			cells = append(cells,
				fmt.Sprintf("%.1f s", results[m.name].warmCPU),
				fmt.Sprintf("%.1f s", results[m.name].coldCPU),
			)
		}
		tw.AppendRow(cells)
	}

	tw.AppendSeparator()
	{
		cells := table.Row{"Mount ready time"}
		for _, m := range modes {
			cells = append(cells, "—", fmt.Sprintf("%.2f s", results[m.name].start.mountSec))
		}
		tw.AppendRow(cells)
	}
	{
		cells := table.Row{"First 1MiB read time"}
		for _, m := range modes {
			cells = append(cells, "—", fmt.Sprintf("%.3f s", results[m.name].start.firstReadSec))
		}
		tw.AppendRow(cells)
	}
	{
		cells := table.Row{"Prewarm cold read"}
		for _, m := range modes {
			cells = append(cells, "—", fmt.Sprintf("%.1f MiB/s", results[m.name].start.prewarmMiBps))
		}
		tw.AppendRow(cells)
	}
	{
		cells := table.Row{"Data fetched (prewarm)"}
		for _, m := range modes {
			cells = append(cells, "—", fmt.Sprintf("%.1f MiB", results[m.name].fetched))
		}
		tw.AppendRow(cells)
	}

	t.Log("\nFUSE vs NBD vs ublk Performance Comparison (local backend)\n" + tw.Render())
}

// ublkAvailable reports whether the ublk_drv module is loadable and its
// control device is present. Mirrors the gating TestUblkTarget does.
func ublkAvailable() bool {
	if out, err := exec.Command("modprobe", "ublk_drv").CombinedOutput(); err != nil {
		_ = out
		return false
	}
	if _, err := os.Stat("/dev/ublk-control"); err != nil {
		return false
	}
	return true
}
