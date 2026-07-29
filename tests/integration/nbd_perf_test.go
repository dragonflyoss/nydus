package integration

// NBD vs FUSE performance comparison (local backend).
//
// Both modes serve the SAME image (bootstrap + blob dir, prefetch disabled,
// separate cache dirs), so the comparison isolates the read transport:
//
//	FUSE: page-cache miss -> FUSE request -> daemon groupmap check + pread
//	      cache file -> FUSE reply. The page cache sits at the FUSE file
//	      level; every metadata call (stat/readdir) is a userspace round
//	      trip.
//	NBD:  page-cache miss -> EROFS -> block layer -> NBD socket -> daemon
//	      pread cache file -> reply. The page cache sits above the block
//	      device; warm hits never reach the daemon, and metadata is served
//	      by the kernel EROFS driver from cached bootstrap blocks.
//
// Methodology (per mode):
//
//  1. cold start: wipe cache + dropCaches, start the daemon; record
//     mount-ready time, first-1MiB read latency, and the full-file cold
//     prewarm throughput (the on-demand fetch path, end to end).
//  2. warmup page cache: short seq read -> fully warm.
//  3. WARM suite (no dropCaches): steady-state, both modes should serve
//     from page cache. Daemon CPU is sampled around the suite — the NBD
//     daemon should burn ~zero here, the FUSE daemon pays per call.
//  4. COLD-PAGE suite (dropCaches before each fio job): warm nydus cache,
//     cold page cache — the headline transport comparison (NBD socket +
//     block layer + device readahead vs FUSE request/reply), both daemons
//     serving pread from the same local cache-file bytes.
//  5. O_DIRECT jobs: bypass the page cache on every request in both modes —
//     the purest per-request round-trip measure, free of the "first pass
//     cold, later passes warm" mixing that time_based direct=0 jobs suffer
//     after dropCaches.
//
// Fairness notes: device readahead (/dev/nbdX, kernel default) and FUSE
// max_readahead are left at their defaults — that is what real deployments
// see — so sequential direct=0 numbers partly reflect readahead policy, not
// just protocol overhead; the direct=1 rows are the controlled comparison.
// The NBD worker count defaults to min(ncpu, 16) kernel connections.
//
// Activation: NBD_RUN_PERF=1 (set by `make test-nbd-perf`). Requires root,
// the nbd kernel module, kernel EROFS support, and fio. Corpus and runtime
// knobs are shared with TestPerf (NYDUSFS_PERF_*).

import (
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

// nbdPerfEnv holds paths, binaries, and process handles for one NBD-vs-FUSE
// performance run.
type nbdPerfEnv struct {
	nydusBin string
	fioBin   string
	device   string

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
}

// coldStart captures the per-mode cold-start metrics.
type coldStart struct {
	mountSec     float64
	firstReadSec float64
	prewarmMiBps float64
}

func TestNbdPerf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}
	if os.Getenv("NBD_RUN_PERF") == "" {
		t.Skip("set NBD_RUN_PERF=1 to enable")
	}
	if !erofsSupported() {
		t.Skip("erofs not in /proc/filesystems — kernel lacks EROFS support")
	}
	device, err := findFreeNbdDevice()
	if err != nil {
		t.Skipf("no free NBD device: %v (is the nbd module loaded? try: modprobe nbd)", err)
	}

	fioBin := mustLookupFio(t)
	nydusBin := mustLookupExecutable(t, "nydus")
	for _, sub := range []string{"nbd", "fuse"} {
		if out, err := exec.Command(nydusBin, sub, "--help").CombinedOutput(); err != nil {
			t.Skipf("nydus binary lacks the %s subcommand; build with --features cli,fuse,nbd: %s", sub, out)
		}
	}

	e := &nbdPerfEnv{nydusBin: nydusBin, fioBin: fioBin, device: device}
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
	for _, d := range []string{e.fuseMnt, e.fuseCache, e.nbdMnt, e.nbdCache, e.nbdLogDir} {
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

	// --- FUSE phase ---
	t.Log("=== FUSE ===")
	fuseStart := e.startFuse(t, targetRel)
	target := filepath.Join(e.fuseMnt, targetRel)
	statDir := filepath.Join(e.fuseMnt, statRel)
	readdirDir := filepath.Join(e.fuseMnt, readdirRel)
	fuseStart.prewarmMiBps = e.prewarm(t, target)
	e.warmupPageCache(t, target)
	cpu0 := processCPUSeconds(e.fuseCmd.Process.Pid)
	fuseWarm := runBenchmarks(t, fioBin, target, statDir, readdirDir, false)
	fuseWarmCPU := processCPUSeconds(e.fuseCmd.Process.Pid) - cpu0
	fuseFetched := cacheDirUsedBytes(e.fuseCache)
	dropCaches(t)
	cpu0 = processCPUSeconds(e.fuseCmd.Process.Pid)
	fuseCold := runBenchmarks(t, fioBin, target, statDir, readdirDir, true)
	fuseColdCPU := processCPUSeconds(e.fuseCmd.Process.Pid) - cpu0
	fuseDirect := e.runDirectJobs(t, target)
	e.stopFuse(t)

	// --- NBD phase ---
	t.Log("=== NBD ===")
	nbdStart := e.startNbd(t, targetRel)
	target = filepath.Join(e.nbdMnt, targetRel)
	statDir = filepath.Join(e.nbdMnt, statRel)
	readdirDir = filepath.Join(e.nbdMnt, readdirRel)
	nbdStart.prewarmMiBps = e.prewarm(t, target)
	e.warmupPageCache(t, target)
	cpu0 = processCPUSeconds(e.nbdCmd.Process.Pid)
	nbdWarm := runBenchmarks(t, fioBin, target, statDir, readdirDir, false)
	nbdWarmCPU := processCPUSeconds(e.nbdCmd.Process.Pid) - cpu0
	nbdFetched := cacheDirUsedBytes(e.nbdCache)
	dropCaches(t)
	cpu0 = processCPUSeconds(e.nbdCmd.Process.Pid)
	nbdCold := runBenchmarks(t, fioBin, target, statDir, readdirDir, true)
	nbdColdCPU := processCPUSeconds(e.nbdCmd.Process.Pid) - cpu0
	nbdDirect := e.runDirectJobs(t, target)
	e.stopNbd(t)

	printNbdPerfTable(t,
		nbdWarm, nbdCold, nbdDirect, fuseWarm, fuseCold, fuseDirect,
		nbdStart, fuseStart,
		nbdWarmCPU, nbdColdCPU, fuseWarmCPU, fuseColdCPU,
		nbdFetched, fuseFetched)
}

// ------------------------------------------------------------------ setup ----

// writeConfigs writes one local-backend storage config per mode: shared blob
// dir, separate cache dirs. Prefetch stays disabled — a background prefetch
// would warm the cache mid-run and corrupt the cold measurements.
func (e *nbdPerfEnv) writeConfigs(t *testing.T) {
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
	t.Log("  wrote configs (local backend, prefetch disabled)")
}

// ----------------------------------------------------------------- daemons ----

// startFuse wipes the FUSE cache, drops the page cache, and starts
// `nydus fuse`. Returns mount-ready time and first-1MiB cold-read time.
func (e *nbdPerfEnv) startFuse(t *testing.T, targetRel string) *coldStart {
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

func (e *nbdPerfEnv) stopFuse(t *testing.T) {
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
func (e *nbdPerfEnv) startNbd(t *testing.T, targetRel string) *coldStart {
	t.Helper()
	wipeCacheDir(e.nbdCache)
	dropCaches(t)

	logFile, err := os.Create(e.nbdLog)
	require.NoError(t, err)
	start := time.Now()
	cmd := exec.Command(e.nydusBin, "nbd",
		"--bootstrap", e.bootstrap,
		"--config", e.nbdConfig,
		"--device", e.device,
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
	t.Logf("  nbd daemon ready (pid=%d, device=%s, %.2fs)", cmd.Process.Pid, e.device, cs.mountSec)

	readStart := time.Now()
	_, err = readSlice(filepath.Join(e.nbdMnt, targetRel), 0, 1)
	require.NoError(t, err, "first cold read failed")
	cs.firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.3fs", cs.firstReadSec)
	return cs
}

func (e *nbdPerfEnv) stopNbd(t *testing.T) {
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
	waitNbdDeviceRelease(t, e.device)
}

func (e *nbdPerfEnv) cleanup(t *testing.T) {
	e.stopFuse(t)
	e.stopNbd(t)
}

// ----------------------------------------------------------------- phases ----

// prewarm cold-reads the entire fio target, filling the nydus cache and
// groupmap for every byte fio will touch, and returns the achieved
// throughput — this IS the end-to-end on-demand fetch path measurement.
func (e *nbdPerfEnv) prewarm(t *testing.T, target string) float64 {
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
func (e *nbdPerfEnv) warmupPageCache(t *testing.T, target string) {
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
func (e *nbdPerfEnv) runDirectJobs(t *testing.T, target string) map[string]*benchResult {
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

func printNbdPerfTable(
	t *testing.T,
	nbdWarm, nbdCold, nbdDirect, fuseWarm, fuseCold, fuseDirect map[string]*benchResult,
	nbdStart, fuseStart *coldStart,
	nbdWarmCPU, nbdColdCPU, fuseWarmCPU, fuseColdCPU float64,
	nbdFetched, fuseFetched float64,
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

	// warm      = warm nydus cache + warm page cache (no dropCaches)
	// cold-page = warm nydus cache + cold page cache (dropCaches per job)
	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.Style().Options.SeparateRows = false
	tw.AppendHeader(table.Row{"Benchmark", "nbd warm", "nbd cold-page", "fuse warm", "fuse cold-page"})
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
			fmtCell(nbdWarm, r.key, r.get, r.unit),
			fmtCell(nbdCold, r.key, r.get, r.unit),
			fmtCell(fuseWarm, r.key, r.get, r.unit),
			fmtCell(fuseCold, r.key, r.get, r.unit),
		})
	}

	// O_DIRECT rows bypass the page cache in both modes, so warm/cold-page
	// makes no difference; rendered once in the cold-page columns.
	tw.AppendSeparator()
	directRows := []row{
		{"Seq Direct BW (128K)", "seq_read_128k_direct", "MiB/s", bw},
		{"Rand Direct IOPS (4K)", "rand_read_4k_direct", "IOPS", iops},
		{"Rand Direct Lat (4K)", "rand_read_4k_direct", "µs", lat},
	}
	for _, r := range directRows {
		tw.AppendRow(table.Row{
			r.label,
			"—", fmtCell(nbdDirect, r.key, r.get, r.unit),
			"—", fmtCell(fuseDirect, r.key, r.get, r.unit),
		})
	}

	tw.AppendSeparator()
	tw.AppendRow(table.Row{
		"Daemon CPU (suite)",
		fmt.Sprintf("%.1f s", nbdWarmCPU), fmt.Sprintf("%.1f s", nbdColdCPU),
		fmt.Sprintf("%.1f s", fuseWarmCPU), fmt.Sprintf("%.1f s", fuseColdCPU),
	})

	tw.AppendSeparator()
	tw.AppendRow(table.Row{
		"Mount ready time",
		"—", fmt.Sprintf("%.2f s", nbdStart.mountSec),
		"—", fmt.Sprintf("%.2f s", fuseStart.mountSec),
	})
	tw.AppendRow(table.Row{
		"First 1MiB read time",
		"—", fmt.Sprintf("%.3f s", nbdStart.firstReadSec),
		"—", fmt.Sprintf("%.3f s", fuseStart.firstReadSec),
	})
	tw.AppendRow(table.Row{
		"Prewarm cold read",
		"—", fmt.Sprintf("%.1f MiB/s", nbdStart.prewarmMiBps),
		"—", fmt.Sprintf("%.1f MiB/s", fuseStart.prewarmMiBps),
	})
	tw.AppendRow(table.Row{
		"Data fetched (prewarm)",
		"—", fmt.Sprintf("%.1f MiB", nbdFetched),
		"—", fmt.Sprintf("%.1f MiB", fuseFetched),
	})

	t.Log("\nNBD vs FUSE Performance Comparison (local backend)\n" + tw.Render())
}
