package e2e

// Unified cold-start performance benchmark: `nydus fuse`, `nydus nbd`,
// `nydus ublk`, and `nydus fanotify` (plus an optional C erofsfuse column)
// all serve the SAME locally built image (bootstrap + blob dir, prefetch
// disabled, separate cache dirs), so the comparison isolates the read
// transport:
//
//	FUSE:      page-cache miss -> FUSE request -> daemon block group map check +
//	           pread cache file -> FUSE reply. Every metadata call is a
//	           userspace round trip.
//	NBD:       page-cache miss -> EROFS -> block layer -> NBD socket ->
//	           daemon pread cache file -> reply. Metadata is served by the
//	           kernel EROFS driver.
//	ublk:      like NBD, but block requests go through ublk_drv's io_uring
//	           SQE/CQE shared memory instead of a kernel socket.
//	fanotify:  kernel EROFS mount over the cache files; a FAN_PRE_ACCESS
//	           event fills missing ranges, warm reads never leave the
//	           kernel (Linux >= 6.15).
//	erofsfuse: the C erofsfuse reference implementation reading the blob
//	           directly (no daemon, no cache).
//
// Methodology (per mode): wipe the nydus cache, drop the page cache, start
// the daemon (recording mount-ready and first-1MiB-read latency), cold-read
// the whole fio target (the end-to-end on-demand fetch path — recorded as
// prewarm throughput), then run every fio job and metadata benchmark with
// the page cache dropped before each job (warm nydus cache, cold page
// cache). Unavailable modes (missing kernel module, old kernel, feature not
// compiled in) are skipped individually and their column omitted.
//
// Activation: NYDUSFS_RUN_BENCH=1 (set by `make test-bench`). Requires root
// and fio; the NBD/ublk modes additionally need their kernel modules and
// EROFS support, fanotify needs Linux >= 6.15 and an ext4 cache dir
// (the Makefile sets TMPDIR).
//
// Tuning knobs (all optional):
//
//	NYDUSFS_PERF_LARGE_FILE_COUNT        Number of large files for read benchmarks (default 8).
//	NYDUSFS_PERF_LARGE_FILE_SIZE         Size of each large file (default 64MiB).
//	NYDUSFS_PERF_MEDIUM_FILE_COUNT       Number of medium files in the corpus (default 256).
//	NYDUSFS_PERF_MEDIUM_FILE             Size of each medium file (default 1MiB).
//	NYDUSFS_PERF_SMALL_FILE_COUNT        Number of small files for the stat benchmark (default 10000).
//	NYDUSFS_PERF_FIO_RUNTIME             Fio benchmark duration in seconds (default 20).
//	NYDUSFS_PERF_FIO_SEQ_NUMJOBS         Sequential-read multi-thread job count (default 4).
//	NYDUSFS_PERF_FIO_RAND_NUMJOBS        Random-read multi-thread job count (default 4).
//	NYDUSFS_PERF_READDIR_DIRS            Number of directories for the readdir corpus (default 128).
//	NYDUSFS_PERF_READDIR_FILES_PER_DIR   Files per directory for the readdir corpus (default 256).
//	NYDUSFS_PERF_META_SECS               Metadata benchmark duration in seconds (default 5).
//	NYDUSFS_PERF_READDIR_META_SECS       Readdir benchmark duration in seconds (default 5).
//	NYDUSFS_PERF_READDIR_PASSES_PER_DIR  Repeated os.ReadDir calls per directory per iteration (default 8).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/require"
)

// Fixed corpus layout produced by corpus.MakePerfCorpus.
const (
	benchTargetRel   = "large/file_0.bin"
	benchStatRel     = "small"
	benchReaddirRel  = "dirs"
	benchXattrRel    = "xattrs"
	benchXattrName   = "user.bench"
	benchErofsfuse   = "erofsfuse"
	benchStopTimeout = 20 * time.Second
)

// benchEnv holds the shared image and per-run paths.
type benchEnv struct {
	nydusBin string
	fioBin   string

	workDir   string
	blobDir   string
	bootstrap string
	blobPath  string // single blob produced by the build, for erofsfuse --device
	nbdDev    string // free /dev/nbdX picked for the NBD mode
}

// benchMode is one serving mode: how to detect availability and how to
// mount/unmount it. All other steps are identical across modes.
type benchMode struct {
	name  string
	skip  string // non-empty: mode unavailable, column omitted
	mnt   string
	cache string // "" when the mode has no nydus cache (erofsfuse)
	start func(t *testing.T) (stop func())
}

// benchModeResult collects every measurement for one mode.
type benchModeResult struct {
	mountSec     float64
	firstReadSec float64
	prewarmMiBps float64
	fetchedMiB   float64 // < 0 when the mode has no cache
	bench        map[string]*benchResult
}

func TestBench(t *testing.T) {
	if os.Getenv("NYDUSFS_RUN_BENCH") == "" {
		t.Skip("set NYDUSFS_RUN_BENCH=1 to enable")
	}
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}

	e := &benchEnv{
		fioBin:   mustLookupFio(t),
		nydusBin: mustLookupExecutable(t, "nydus"),
	}
	e.workDir = t.TempDir()
	corpusDir := filepath.Join(e.workDir, "corpus")
	e.blobDir = filepath.Join(e.workDir, "blobs")
	e.bootstrap = filepath.Join(e.workDir, "bootstrap.boot")

	t.Log("Generating performance corpus...")
	corpus.MakePerfCorpus(t, corpusDir)
	t.Log("Building NydusFS image (chunksize=1MiB)...")
	e.blobPath = buildNydusFSImageToDir(t, e.nydusBin, e.bootstrap, e.blobDir, corpusDir, 1024*1024)

	modes := e.buildModes(t)
	results := make(map[string]*benchModeResult, len(modes))
	for _, m := range modes {
		if m.skip != "" {
			t.Logf("=== %s: SKIPPED (%s) ===", m.name, m.skip)
			continue
		}
		t.Logf("=== %s ===", m.name)
		results[m.name] = e.runMode(t, m)
	}
	require.NotEmpty(t, results, "no serving mode is available on this host")

	printBenchTable(t, modes, results)
}

// runMode measures one mode end to end: cold start, prewarm, then the cold
// page-cache benchmark suite.
func (e *benchEnv) runMode(t *testing.T, m *benchMode) *benchModeResult {
	t.Helper()
	if m.cache != "" {
		wipeCacheDir(m.cache)
	}
	dropCaches(t)

	res := &benchModeResult{fetchedMiB: -1}
	mountStart := time.Now()
	stop := m.start(t)
	defer stop()
	res.mountSec = time.Since(mountStart).Seconds()
	t.Logf("  mount ready: %.2fs", res.mountSec)

	target := filepath.Join(m.mnt, benchTargetRel)
	readStart := time.Now()
	_, err := readSlice(target, 0, 1)
	require.NoError(t, err, "first cold read failed")
	res.firstReadSec = time.Since(readStart).Seconds()
	t.Logf("  first 1MiB cold read: %.3fs", res.firstReadSec)

	// Cold-read the whole fio target: fills the nydus cache and block group map for
	// every byte fio will touch, and IS the end-to-end on-demand fetch path.
	prewarmStart := time.Now()
	n := readWhole(t, target)
	res.prewarmMiBps = float64(n) / (1 << 20) / time.Since(prewarmStart).Seconds()
	t.Logf("  prewarm: %.1f MiB cold-read at %.1f MiB/s", float64(n)/(1<<20), res.prewarmMiBps)

	statDir := filepath.Join(m.mnt, benchStatRel)
	res.bench = runBenchmarks(t, e.fioBin, target, statDir, filepath.Join(m.mnt, benchReaddirRel))
	dropCaches(t)
	addMetaBenchmarks(t, res.bench, filepath.Join(m.mnt, benchXattrRel), benchXattrName, statDir)
	if m.cache != "" {
		res.fetchedMiB = cacheDirUsedBytes(m.cache)
	}
	return res
}

// ------------------------------------------------------------------ modes ----

// buildModes prepares the per-mode dirs/configs and probes availability.
// A mode that cannot run on this host gets a skip reason instead of failing
// the whole benchmark.
func (e *benchEnv) buildModes(t *testing.T) []*benchMode {
	t.Helper()

	subOK := func(sub string) string {
		if out, err := exec.Command(e.nydusBin, sub, "--help").CombinedOutput(); err != nil {
			return fmt.Sprintf("nydus binary lacks the %s subcommand (build with --features cli,%s): %s", sub, sub, firstLine(out))
		}
		return ""
	}
	newMode := func(name string, start func(t *testing.T) func()) *benchMode {
		m := &benchMode{
			name:  name,
			mnt:   filepath.Join(e.workDir, name+"-mnt"),
			cache: filepath.Join(e.workDir, name+"-cache"),
			start: start,
		}
		require.NoError(t, os.MkdirAll(m.mnt, 0755))
		require.NoError(t, os.MkdirAll(m.cache, 0755))
		e.writeConfig(t, name, m.cache)
		return m
	}

	fuse := newMode("fuse", e.startFuse)
	fuse.skip = subOK("fuse")

	nbd := newMode("nbd", e.startNbd)
	if nbd.skip = subOK("nbd"); nbd.skip == "" {
		if !erofsSupported() {
			nbd.skip = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if dev, err := findFreeNbdDevice(); err != nil {
			nbd.skip = fmt.Sprintf("no free NBD device: %v (try: modprobe nbd)", err)
		} else {
			e.nbdDev = dev
		}
	}

	ublk := newMode("ublk", e.startUblk)
	if ublk.skip = subOK("ublk"); ublk.skip == "" {
		if !erofsSupported() {
			ublk.skip = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if !ublkAvailable() {
			ublk.skip = "ublk_drv unavailable (needs Linux 6.0+ and /dev/ublk-control; try: modprobe ublk_drv)"
		}
	}

	fan := newMode("fanotify", e.startFanotify)
	if fan.skip = subOK("fanotify"); fan.skip == "" {
		if maj, min := kernelVersion(t); maj < 6 || (maj == 6 && min < 15) {
			fan.skip = fmt.Sprintf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", maj, min)
		}
	}

	cerofs := &benchMode{
		name:  benchErofsfuse,
		mnt:   filepath.Join(e.workDir, "erofsfuse-mnt"),
		start: e.startErofsfuse,
	}
	require.NoError(t, os.MkdirAll(cerofs.mnt, 0755))
	if _, err := lookupCErofsFuseExecutable(); err != nil {
		cerofs.skip = err.Error()
	}

	return []*benchMode{fuse, nbd, ublk, fan, cerofs}
}

// writeConfig writes one local-backend storage config per mode: shared blob
// dir, separate cache dirs. Prefetch stays disabled — a background prefetch
// would warm the cache mid-run and corrupt the cold measurements.
func (e *benchEnv) writeConfig(t *testing.T, name, cacheDir string) {
	t.Helper()
	config := fmt.Sprintf(
		"backend:\n  type: local\n  config:\n    dir: %s\nstorage:\n  dir: %s\nprefetch:\n  scope: none\n",
		e.blobDir, cacheDir,
	)
	require.NoError(t, os.WriteFile(e.configPath(name), []byte(config), 0644))
}

func (e *benchEnv) configPath(name string) string {
	return filepath.Join(e.workDir, name+".yaml")
}

func (e *benchEnv) logPath(name string) string {
	return filepath.Join(e.workDir, name+".log")
}

func (e *benchEnv) logDir(name string) string {
	d := filepath.Join(e.workDir, name+"-logs")
	_ = os.MkdirAll(d, 0755)
	return d
}

// ---------------------------------------------------------------- daemons ----

// spawnDaemon starts cmd with stdout/stderr appended to logPath and returns
// the exited channel.
func spawnDaemon(t *testing.T, cmd *exec.Cmd, logPath string) chan struct{} {
	t.Helper()
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	_ = logFile.Close()
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	return exited
}

// terminateDaemon SIGTERMs cmd and waits up to benchStopTimeout before
// killing it.
func terminateDaemon(cmd *exec.Cmd, exited chan struct{}) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	select {
	case <-exited:
		return
	default:
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(benchStopTimeout):
		_ = cmd.Process.Kill()
		<-exited
	}
}

func (e *benchEnv) startFuse(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "fuse-mnt")
	cmd := exec.Command(e.nydusBin, "fuse",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("fuse"),
		"--mountpoint", mnt,
	)
	exited := spawnDaemon(t, cmd, e.logPath("fuse"))
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "fuse daemon exited during startup", "%s", readFileOrEmpty(e.logPath("fuse")))
		default:
		}
		return isMountpoint(mnt)
	}, 60*time.Second, 200*time.Millisecond, "fuse daemon did not mount:\n%s", readFileOrEmpty(e.logPath("fuse")))
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			unmountFuse(mnt)
		}
	}
}

func (e *benchEnv) startNbd(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "nbd-mnt")
	cmd := exec.Command(e.nydusBin, "nbd",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("nbd"),
		"--device", e.nbdDev,
		"--mountpoint", mnt,
		"--log-level", "info",
		"--log-dir", e.logDir("nbd"),
	)
	exited := spawnDaemon(t, cmd, e.logPath("nbd"))
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "nbd daemon exited during startup", "%s", readFileOrEmpty(e.logPath("nbd")))
		default:
		}
		return isMountpoint(mnt)
	}, 60*time.Second, 200*time.Millisecond, "nbd daemon did not mount:\n%s", readFileOrEmpty(e.logPath("nbd")))
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
		waitNbdDeviceRelease(t, e.nbdDev)
	}
}

func (e *benchEnv) startUblk(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "ublk-mnt")
	logFile, err := os.Create(e.logPath("ublk"))
	require.NoError(t, err)
	cmd := exec.Command(e.nydusBin, "ublk",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("ublk"),
		"--log-level", "info",
		"--log-dir", e.logDir("ublk"),
	)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()

	// The daemon prints the /dev/ublkbN path on stdout once ready; tee every
	// line into the log file so it is preserved.
	var devPath string
	go func() {
		s := bufio.NewScanner(stdoutPipe)
		for s.Scan() {
			line := s.Text()
			_, _ = logFile.WriteString(line + "\n")
			trimmed := strings.TrimSpace(line)
			if devPath == "" && strings.HasPrefix(trimmed, "/dev/ublkb") {
				devPath = trimmed
			}
		}
	}()

	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "ublk daemon exited during startup", "%s", readFileOrEmpty(e.logPath("ublk")))
		default:
		}
		return devPath != ""
	}, 60*time.Second, 200*time.Millisecond, "ublk daemon did not report a device path:\n%s", readFileOrEmpty(e.logPath("ublk")))
	require.Eventually(t, func() bool {
		_, err := os.Stat(devPath)
		return err == nil
	}, 10*time.Second, 200*time.Millisecond, "%s did not appear", devPath)

	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", devPath, mnt).CombinedOutput()
	require.NoError(t, err, "failed to mount %s as erofs: %s", devPath, out)
	return func() {
		// Unmount BEFORE stopping the daemon: it serves I/O for its own
		// block device, so unmounting while it exits would deadlock.
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
		terminateDaemon(cmd, exited)
	}
}

func (e *benchEnv) startFanotify(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "fanotify-mnt")
	cmd := exec.Command(e.nydusBin, "fanotify",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("fanotify"),
		"--mountpoint", mnt,
		"--log-level", "info",
		"--log-dir", e.logDir("fanotify"),
	)
	exited := spawnDaemon(t, cmd, e.logPath("fanotify"))
	logs := func() string {
		var b strings.Builder
		b.Write(readFileOrEmpty(e.logPath("fanotify")))
		entries, _ := os.ReadDir(e.logDir("fanotify"))
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				b.Write(readFileOrEmpty(filepath.Join(e.logDir("fanotify"), entry.Name())))
			}
		}
		return b.String()
	}
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "fanotify daemon exited during startup", "%s", logs())
		default:
		}
		return isMountpoint(mnt) && strings.Contains(logs(), "event loop ready")
	}, 60*time.Second, 200*time.Millisecond, "fanotify daemon did not mount:\n%s", logs())
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
	}
}

func (e *benchEnv) startErofsfuse(t *testing.T) func() {
	t.Helper()
	bin := mustLookupCErofsFuse(t)
	return mountCErofsFuse(t, bin, e.bootstrap, filepath.Join(e.workDir, "erofsfuse-mnt"), e.blobPath)
}

// ublkAvailable reports whether the ublk_drv module is loadable and its
// control device is present. Mirrors the gating TestUblkTarget does.
func ublkAvailable() bool {
	if err := exec.Command("modprobe", "ublk_drv").Run(); err != nil {
		return false
	}
	if _, err := os.Stat("/dev/ublk-control"); err != nil {
		return false
	}
	return true
}

// cacheDirUsedBytes returns the allocated (not apparent) MiB of the blob
// cache files in cacheDir.
func cacheDirUsedBytes(cacheDir string) float64 {
	var total int64
	matches, _ := filepath.Glob(filepath.Join(cacheDir, "*.blob.data"))
	for _, m := range matches {
		total += usedBytes(m)
	}
	return float64(total) / (1024 * 1024)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ----------------------------------------------------------------- output ----

func printBenchTable(t *testing.T, modes []*benchMode, results map[string]*benchModeResult) {
	type row struct {
		label string
		key   string
		unit  string
		get   func(r *benchResult) float64
	}

	bw := func(r *benchResult) float64 { return r.ReadBW }
	iops := func(r *benchResult) float64 { return r.ReadIOPS }
	lat := func(r *benchResult) float64 { return r.ReadLat }

	var active []*benchMode
	for _, m := range modes {
		if results[m.name] != nil {
			active = append(active, m)
		}
	}

	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.Style().Options.SeparateRows = false
	header := table.Row{"Benchmark"}
	colCfg := []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}}
	for i, m := range active {
		header = append(header, m.name)
		colCfg = append(colCfg, table.ColumnConfig{Number: 2 + i, Align: text.AlignRight})
	}
	tw.AppendHeader(header)
	tw.SetColumnConfigs(colCfg)

	appendRow := func(label string, cell func(res *benchModeResult) string) {
		cells := table.Row{label}
		for _, m := range active {
			cells = append(cells, cell(results[m.name]))
		}
		tw.AppendRow(cells)
	}

	appendRow("Mount ready", func(res *benchModeResult) string {
		return fmt.Sprintf("%.2f s", res.mountSec)
	})
	appendRow("First 1MiB cold read", func(res *benchModeResult) string {
		return fmt.Sprintf("%.3f s", res.firstReadSec)
	})
	appendRow("Prewarm (full-file cold fetch)", func(res *benchModeResult) string {
		return fmt.Sprintf("%.1f MiB/s", res.prewarmMiBps)
	})
	appendRow("Data fetched (prewarm)", func(res *benchModeResult) string {
		if res.fetchedMiB < 0 {
			return "—"
		}
		return fmt.Sprintf("%.1f MiB", res.fetchedMiB)
	})

	tw.AppendSeparator()
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
		{"Listxattr IOPS", "listxattr", "IOPS", iops},
		{"Listxattr Latency", "listxattr", "µs", lat},
		{"Getxattr IOPS", "getxattr", "IOPS", iops},
		{"Getxattr Latency", "getxattr", "µs", lat},
		{"Readdir+stat (ls -l) IOPS", "readdir_stat", "IOPS", iops},
		{"Readdir+stat (ls -l) Latency", "readdir_stat", "µs", lat},
	}
	for _, r := range rows {
		appendRow(r.label, func(res *benchModeResult) string {
			if br, ok := res.bench[r.key]; ok && br != nil {
				return fmt.Sprintf("%.1f %s", r.get(br), r.unit)
			}
			return "—"
		})
	}

	var skipped []string
	for _, m := range modes {
		if m.skip != "" {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", m.name, m.skip))
		}
	}
	suffix := ""
	if len(skipped) > 0 {
		suffix = "\nSkipped modes: " + strings.Join(skipped, "; ")
	}
	t.Log("\nCold-start Performance Comparison (local backend, cold page cache)\n" + tw.Render() + suffix)
}

// ----------------------------------------------------------- shared suite ----

// runBenchmarks executes the full I/O and metadata benchmark suite and
// returns the per-benchmark results keyed by name. dropCaches is called
// before each fio job to force cache-miss reads. Every job passes
// --invalidate=0: fio's default invalidate=1 fadvises the target file out of
// the page cache at job start — cache state must be controlled by dropCaches
// alone.
func runBenchmarks(t *testing.T, fioBin, targetFile, statDir, readdirDir string) map[string]*benchResult {
	require.FileExists(t, targetFile)

	fioRuntime := corpus.EnvInt("NYDUSFS_PERF_FIO_RUNTIME", 20)
	fioSeqNumjobs := corpus.EnvInt("NYDUSFS_PERF_FIO_SEQ_NUMJOBS", 4)
	fioRandNumjobs := corpus.EnvInt("NYDUSFS_PERF_FIO_RAND_NUMJOBS", 4)
	results := make(map[string]*benchResult)

	dropCaches(t)
	results["seq_read_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read", "--filename=" + targetFile,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["rand_read_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read", "--filename=" + targetFile,
		"--rw=randread", "--bs=128k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["seq_read_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4k", "--filename=" + targetFile,
		"--rw=read", "--bs=4k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["rand_read_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4k", "--filename=" + targetFile,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["seq_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + targetFile,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["rand_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + targetFile,
		"--rw=randread", "--bs=128k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["seq_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + targetFile,
		"--rw=read", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["rand_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + targetFile,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["stat"] = benchStat(t, statDir)

	dropCaches(t)
	results["readdir"] = benchReaddir(t, readdirDir)
	return results
}

// benchStat repeatedly stats every file in dir for the configured metadata duration and
// reports the achieved ops/s and latency.
func benchStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

	var files []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}

		return nil
	})
	require.NotEmpty(t, files)

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, f := range files {
			_, _ = os.Stat(f)
		}

		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(files))
	return &benchResult{
		Name:     "stat",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchReaddir repeatedly reads every subdirectory of dir for the configured
// metadata duration and reports the achieved ops/s and latency.
func benchReaddir(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_READDIR_META_SECS", 5)) * time.Second
	passesPerDir := corpus.EnvInt("NYDUSFS_PERF_READDIR_PASSES_PER_DIR", 8)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(dir, entry.Name()))
		}
	}
	require.NotEmpty(t, dirs)

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, dir := range dirs {
			for range passesPerDir {
				_, _ = os.ReadDir(dir)
			}
		}

		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(dirs) * passesPerDir)
	return &benchResult{
		Name:     "readdir",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// addMetaBenchmarks runs the metadata-only benchmarks (listxattr, getxattr,
// readdir+stat) and inserts their results into the provided map.
func addMetaBenchmarks(t *testing.T, results map[string]*benchResult, xattrDir, xattrName, statDir string) {
	t.Helper()

	if xattrDir != "" {
		results["listxattr"] = benchListxattr(t, xattrDir)
		if xattrName != "" {
			results["getxattr"] = benchGetxattr(t, xattrDir, xattrName)
		}
	}
	results["readdir_stat"] = benchReaddirStat(t, statDir)
}

// benchListxattr repeatedly calls listxattr on every regular file in dir for
// the configured metadata duration and reports the achieved ops/s and latency.
// Returns nil when no regular files are found.
func benchListxattr(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil
	}

	buf := make([]byte, 512)
	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, f := range files {
			_, _ = syscall.Listxattr(f, buf)
		}
		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(files))
	return &benchResult{
		Name:     "listxattr",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchGetxattr repeatedly calls getxattr(name) on every regular file in dir
// for the configured metadata duration and reports the achieved ops/s and
// latency. Returns nil when no regular files are found.
func benchGetxattr(t *testing.T, dir, xattrName string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil
	}

	buf := make([]byte, 256)
	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, f := range files {
			_, _ = syscall.Getxattr(f, xattrName, buf)
		}
		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(files))
	return &benchResult{
		Name:     "getxattr",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchReaddirStat repeatedly reads dir entries and lstats each one,
// simulating an "ls -l" workload, for the configured metadata duration.
// Returns nil when dir has no entries.
func benchReaddirStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

	// Verify the directory is non-empty.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	if len(entries) == 0 {
		return nil
	}

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(dir)
		for _, ent := range ents {
			_, _ = os.Lstat(filepath.Join(dir, ent.Name()))
		}
		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations)
	return &benchResult{
		Name:     "readdir_stat",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchResult is the per-job summary extracted from a benchmark run.
type benchResult struct {
	// A short name identifying the benchmark, e.g. "seq_read_128k".
	Name string

	// Throughput in MB/s.
	ReadBW float64

	// I/O operations per second.
	ReadIOPS float64

	// Average latency in microseconds.
	ReadLat float64
}

// fioJSONResult mirrors the subset of fio's JSON output we consume.
type fioJSONResult struct {
	Jobs []struct {
		Jobname string `json:"jobname"`
		Read    struct {
			Bw    float64 `json:"bw"` // KB/s
			Iops  float64 `json:"iops"`
			LatNs struct {
				Mean float64 `json:"mean"` // Nanoseconds
			} `json:"lat_ns"`
		} `json:"read"`
	} `json:"jobs"`
}

// runFio runs a single fio job with JSON output and returns its summary.
func runFio(t *testing.T, fioBin string, args []string) *benchResult {
	out, err := exec.Command(fioBin, append([]string{"--output-format=json"}, args...)...).CombinedOutput()
	require.NoError(t, err, "fio failed: %s", string(out))

	var result fioJSONResult
	require.NoError(t, json.Unmarshal(out, &result))
	require.NotEmpty(t, result.Jobs)

	job := result.Jobs[0]
	return &benchResult{
		Name:     job.Jobname,
		ReadBW:   job.Read.Bw / 1024.0,
		ReadIOPS: job.Read.Iops,
		ReadLat:  job.Read.LatNs.Mean / 1000.0,
	}
}
