package integration

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/erofs/erofs-utils-rust/tests/integration/texture"
)

// TestPerf runs fio-based I/O benchmarks and Go-based metadata benchmarks
// against Rust `lepton mount`, optionally comparing with C erofsfuse.
//
// Enable:        EROFS_RUN_PERF=1
// C comparison:  EROFS_C_FUSE=/path/to/erofsfuse (auto-detected if omitted)
// Tuning:
//   EROFS_PERF_LARGE_FILE_COUNT  number of large files for read benchmarks (default: 8)
//   EROFS_PERF_LARGE_FILE_MB     size in MiB of each large file (default: 64)
//   EROFS_PERF_MEDIUM_FILE_COUNT number of medium files in corpus (default: 256)
//   EROFS_PERF_MEDIUM_FILE_MB    size in MiB of each medium file (default: 1)
//   EROFS_PERF_SMALL_FILE_COUNT  number of small files for stat benchmark (default: 10000)
//   EROFS_PERF_FIO_SECS          fio benchmark duration in seconds (default: 20)
//   EROFS_PERF_SEQ_THREADS       seq-read multi-thread job count (default: 4)
//   EROFS_PERF_READDIR_DIRS   number of directories for readdir corpus (default: 128)
//   EROFS_PERF_READDIR_FILES  files per directory for readdir corpus (default: 256)
//   EROFS_PERF_READDIR_PASSES repeated os.ReadDir calls per directory in one iteration (default: 8)
//   EROFS_PERF_META_SECS      metadata benchmark duration in seconds (default: 5)
func TestPerf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("EROFS_RUN_PERF") == "" {
		t.Skip("set EROFS_RUN_PERF=1 to enable")
	}

	mkfsBin := requireBinary(t, "lepton")
	rustFuse := requireBinary(t, "lepton")
	cFuse := findCFuse()
	fioBin := requireFio(t)

	tmpDir := "/tmp/erofs-perf"
	_ = os.RemoveAll(tmpDir)
	require.NoError(t, os.MkdirAll(tmpDir, 0755))

	corpusDir := filepath.Join(tmpDir, "corpus")
	img := filepath.Join(tmpDir, "test.erofs")
	blob := filepath.Join(tmpDir, "test.blob")
	mntDir := filepath.Join(tmpDir, "mnt")

	// Generate corpus (~260 MB)
	t.Log("Generating performance corpus...")
	makePerfCorpus(t, corpusDir)

	// Build EROFS image with 1 MB chunks (realistic)
	t.Log("Building EROFS image (chunksize=1M)...")
	out, err := exec.Command(mkfsBin, "build", img,
		"--blobdev", blob, "--chunksize", "1048576", corpusDir).CombinedOutput()
	require.NoError(t, err, "lepton build: %s", string(out))

	// --- Rust lepton mount ---
	t.Log("Benchmarking Rust lepton mount...")
	dropCaches()
	unmount := mountEROFS(t, rustFuse, img, blob, mntDir)
	rustResults := runBenchmarks(t, fioBin, mntDir)
	unmount()

	// --- C erofsfuse (optional) ---
	var cResults map[string]*benchResult
	if cFuse != "" {
		t.Logf("Benchmarking C erofsfuse (%s)...", cFuse)
		dropCaches()
		unmount = mountCErofsFuse(t, cFuse, img, blob, mntDir)
		cResults = runBenchmarks(t, fioBin, mntDir)
		unmount()
	} else {
		t.Log("C erofsfuse not found, skipping comparison (set EROFS_C_FUSE=path)")
	}

	printResultsTable(t, rustResults, cResults)
}

// ---------- perf corpus generation ----------

func makePerfCorpus(t *testing.T, dir string) {
	c := texture.NewCorpus(t, dir)
	largeFileCount := envInt("EROFS_PERF_LARGE_FILE_COUNT", 8)
	largeFileMB := envInt("EROFS_PERF_LARGE_FILE_MB", 64)
	mediumFileCount := envInt("EROFS_PERF_MEDIUM_FILE_COUNT", 256)
	mediumFileMB := envInt("EROFS_PERF_MEDIUM_FILE_MB", 1)
	smallFileCount := envInt("EROFS_PERF_SMALL_FILE_COUNT", 10000)
	readdirDirCount := envInt("EROFS_PERF_READDIR_DIRS", 128)
	readdirFilesPerDir := envInt("EROFS_PERF_READDIR_FILES", 256)

	// Larger corpus for read benchmarks to amplify sequential/random read cost.
	for i := 0; i < largeFileCount; i++ {
		c.CreateLargeFile(t, fmt.Sprintf("large/file_%d.bin", i), largeFileMB)
	}
	for i := 0; i < mediumFileCount; i++ {
		c.CreateRandomFile(t, fmt.Sprintf("medium/file_%04d.bin", i), mediumFileMB<<20)
	}
	for i := 0; i < smallFileCount; i++ {
		c.CreateFile(t, fmt.Sprintf("small/file_%04d.txt", i),
			[]byte(fmt.Sprintf("content of small file %d\n", i)))
	}
	// Large directory fanout to amplify readdir cost and trigger repeated FUSE readdir calls.
	for d := 0; d < readdirDirCount; d++ {
		for f := 0; f < readdirFilesPerDir; f++ {
			c.CreateFile(t, fmt.Sprintf("dirs/d%02d/f%03d.txt", d, f),
				[]byte(fmt.Sprintf("d%d/f%d", d, f)))
		}
	}
}

// ---------- C fuse discovery & mount ----------

func findCFuse() string {
	if p := os.Getenv("EROFS_C_FUSE"); p != "" {
		return p
	}
	candidates := []string{
		"/home/imeoer/code/erofs-utils/fuse/erofsfuse",
		"/usr/bin/erofsfuse",
		"/usr/local/bin/erofsfuse",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("erofsfuse"); err == nil {
		return p
	}
	return ""
}

func requireFio(t *testing.T) string {
	p, err := exec.LookPath("fio")
	require.NoError(t, err, "fio not found; install with: apt-get install fio")
	return p
}

func mountCErofsFuse(t *testing.T, cFuseBin, img, blobdev, mnt string) (cleanup func()) {
	_ = exec.Command("fusermount", "-u", mnt).Run()
	require.NoError(t, os.MkdirAll(mnt, 0755))

	// C erofsfuse: erofsfuse [--device=BLOB] IMAGE MOUNTPOINT -f
	args := []string{}
	if blobdev != "" {
		args = append(args, "--device="+blobdev)
	}
	args = append(args, img, mnt, "-f")

	cmd := exec.Command(cFuseBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "erofsfuse start")

	mounted := false
	for i := 0; i < 40; i++ {
		if isMountpoint(mnt) {
			mounted = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	require.True(t, mounted, "erofsfuse failed to mount within 10s")

	return func() {
		_ = exec.Command("fusermount", "-u", mnt).Run()
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
			}
		}
	}
}

func dropCaches() {
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0644)
	time.Sleep(500 * time.Millisecond)
}

// ---------- fio execution ----------

type benchResult struct {
	Name     string
	ReadBW   float64 // MB/s
	ReadIOPS float64
	ReadLat  float64 // average latency in µs
}

type fioJSON struct {
	Jobs []struct {
		Jobname string `json:"jobname"`
		Read    struct {
			Bw    float64 `json:"bw"` // KB/s
			Iops  float64 `json:"iops"`
			LatNs struct {
				Mean float64 `json:"mean"`
			} `json:"lat_ns"`
		} `json:"read"`
	} `json:"jobs"`
}

func runFioJob(t *testing.T, fioBin string, args []string) *benchResult {
	full := append([]string{"--output-format=json"}, args...)
	out, err := exec.Command(fioBin, full...).CombinedOutput()
	require.NoError(t, err, "fio failed: %s", string(out))

	var result fioJSON
	require.NoError(t, json.Unmarshal(out, &result), "fio JSON parse")
	require.NotEmpty(t, result.Jobs)

	job := result.Jobs[0]
	return &benchResult{
		Name:     job.Jobname,
		ReadBW:   job.Read.Bw / 1024.0,
		ReadIOPS: job.Read.Iops,
		ReadLat:  job.Read.LatNs.Mean / 1000.0,
	}
}

// ---------- benchmark suite ----------

func runBenchmarks(t *testing.T, fioBin, mntDir string) map[string]*benchResult {
	results := make(map[string]*benchResult)
	largeFile := filepath.Join(mntDir, "large/file_0.bin")
	fioSeconds := envInt("EROFS_PERF_FIO_SECS", 20)
	seqThreads := envInt("EROFS_PERF_SEQ_THREADS", 4)
	require.FileExists(t, largeFile)

	// 1. Sequential read throughput (128K blocks)
	dropCaches()
	results["seq_read"] = runFioJob(t, fioBin, []string{
		"--name=seq_read", "--filename=" + largeFile,
		"--rw=read", "--bs=128k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioSeconds), "--time_based", "--readonly",
	})

	// 2. Random read IOPS (4K blocks)
	dropCaches()
	results["rand_read_4k"] = runFioJob(t, fioBin, []string{
		"--name=rand_read_4k", "--filename=" + largeFile,
		"--rw=randread", "--bs=4k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioSeconds), "--time_based", "--readonly",
	})

	// 3. Multi-threaded sequential read (4 threads on same file)
	dropCaches()
	results["seq_read_4t"] = runFioJob(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + largeFile,
		"--rw=read", "--bs=128k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", seqThreads), fmt.Sprintf("--runtime=%d", fioSeconds), "--time_based",
		"--readonly", "--group_reporting",
	})

	// 4. Metadata: stat
	dropCaches()
	results["stat"] = benchStat(t, filepath.Join(mntDir, "small"))

	// 5. Metadata: readdir
	dropCaches()
	results["readdir"] = benchReaddir(t, filepath.Join(mntDir, "dirs"))

	return results
}

// ---------- Go metadata benchmarks ----------

func benchStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(envInt("EROFS_PERF_META_SECS", 5)) * time.Second
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

func benchReaddir(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(envInt("EROFS_PERF_META_SECS", 5)) * time.Second
	passesPerDir := envInt("EROFS_PERF_READDIR_PASSES", 8)
	var dirs []string
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(dir, e.Name()))
		}
	}
	require.NotEmpty(t, dirs)

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, d := range dirs {
			for pass := 0; pass < passesPerDir; pass++ {
				_, _ = os.ReadDir(d)
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

func envInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

// ---------- result table ----------

func printResultsTable(t *testing.T, rust, c map[string]*benchResult) {
	type row struct {
		label string
		key   string
		unit  string
		get   func(r *benchResult) float64
	}
	rows := []row{
		{"Sequential Read (128K)", "seq_read", "MB/s", func(r *benchResult) float64 { return r.ReadBW }},
		{"Random Read (4K)", "rand_read_4k", "IOPS", func(r *benchResult) float64 { return r.ReadIOPS }},
		{"Random Read (4K) Lat", "rand_read_4k", "µs", func(r *benchResult) float64 { return r.ReadLat }},
		{"Seq Read 4-thread", "seq_read_4t", "MB/s", func(r *benchResult) float64 { return r.ReadBW }},
		{"Stat", "stat", "IOPS", func(r *benchResult) float64 { return r.ReadIOPS }},
		{"Stat Latency", "stat", "µs", func(r *benchResult) float64 { return r.ReadLat }},
		{"Readdir", "readdir", "IOPS", func(r *benchResult) float64 { return r.ReadIOPS }},
		{"Readdir Latency", "readdir", "µs", func(r *benchResult) float64 { return r.ReadLat }},
	}

	var sb strings.Builder
	sb.WriteString("\n")
	if c != nil {
		sb.WriteString(fmt.Sprintf("%-25s %8s  %12s  %12s  %8s\n", "Benchmark", "Unit", "Rust", "C", "Ratio"))
		sb.WriteString(strings.Repeat("-", 72) + "\n")
	} else {
		sb.WriteString(fmt.Sprintf("%-25s %8s  %12s\n", "Benchmark", "Unit", "Rust"))
		sb.WriteString(strings.Repeat("-", 50) + "\n")
	}

	for _, r := range rows {
		rustR := rust[r.key]
		if rustR == nil {
			continue
		}
		rustVal := r.get(rustR)
		if c != nil {
			cR := c[r.key]
			if cR == nil {
				continue
			}
			cVal := r.get(cR)
			ratio := ""
			if cVal > 0 {
				pct := rustVal / cVal
				if r.unit == "µs" {
					// For latency, lower is better
					pct = cVal / rustVal
				}
				ratio = fmt.Sprintf("%.2fx", pct)
			}
			sb.WriteString(fmt.Sprintf("%-25s %8s  %12.1f  %12.1f  %8s\n",
				r.label, r.unit, rustVal, cVal, ratio))
		} else {
			sb.WriteString(fmt.Sprintf("%-25s %8s  %12.1f\n", r.label, r.unit, rustVal))
		}
	}
	t.Log(sb.String())
}
