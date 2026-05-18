package integration

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/lepton/tests/integration/texture"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/require"
)

// TestPerf runs fio-based I/O benchmarks and Go-based metadata benchmarks
// against the Rust `lepton mount`, optionally comparing the results with
// the C `erofsfuse` implementation.
//
// Activation:
//
//	LEPTONFS_RUN_PERF=1                     enable the test (off by default).
//	                                     (auto-detected when omitted).
//
// Tuning knobs (all optional):
//
//	LEPTONFS_PERF_LARGE_FILE_COUNT        Number of large files for read benchmarks (default 8).
//	LEPTONFS_PERF_LARGE_FILE_SIZE         Size of each large file (default 64MiB).
//	LEPTONFS_PERF_MEDIUM_FILE_COUNT       Number of medium files in the corpus (default 256).
//	LEPTONFS_PERF_MEDIUM_FILE             Size of each medium file (default 1Mib).
//	LEPTONFS_PERF_SMALL_FILE_COUNT        Number of small files for the stat benchmark (default 10000).
//	LEPTONFS_PERF_FIO_RUNTIME             Fio benchmark duration in seconds (default 20).
//	LEPTONFS_PERF_FIO_SEQ_NUMJOBS         Sequential-read multi-thread job count (default 4).
//	LEPTONFS_PERF_FIO_RAND_NUMJOBS        Random-read multi-thread job count (default 4).
//	LEPTONFS_PERF_READDIR_DIRS            Number of directories for the readdir corpus (default 128).
//	LEPTONFS_PERF_READDIR_FILES_PER_DIR   Files per directory for the readdir corpus (default 256).
//	LEPTONFS_PERF_READDIR_META_SECS       Metadata benchmark duration in seconds (default 5).
//	LEPTONFS_PERF_READDIR_PASSES_PER_DIR  Repeated os.ReadDir calls per directory per iteration (default 8).
func TestPerf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}

	if os.Getenv("LEPTONFS_RUN_PERF") == "" {
		t.Skip("set LEPTONFS_RUN_PERF=1 to enable")
	}

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	imagePath := filepath.Join(tmpDir, "test.image")
	blobdev := filepath.Join(tmpDir, "test.blobdev")
	mntDir := filepath.Join(tmpDir, "mnt")

	// Ensure erofsfuse is built and available if we're going to benchmark it.
	setupCErofsfuse(t)
	fioBin := mustLookupFio(t)
	leptonBin := mustLookupExecutable(t, "lepton")
	cErofsFuseBin := mustLookupCErofsFuse(t)

	// Generate the performance corpus (~260 MiB by default).
	t.Log("Generating performance corpus...")
	texture.MakePerfCorpus(t, corpusDir)

	// Build the LeptonFS image with 1 MiB chunks (a realistic chunk size).
	t.Log("Building LeptonFS image (chunksize=1MiB)...")
	buildLeptonFSImage(t, leptonBin, imagePath, blobdev, corpusDir, 1024*1024)

	// Benchmark the Rust lepton mount implementation.
	t.Log("Benchmarking lepton...")
	unmount := mountLepton(t, leptonBin, imagePath, blobdev, mntDir)
	leptonFSResults := runBenchmarks(t, fioBin, mntDir)
	unmount()

	// Benchmark the C erofsfuse implementation for comparison.
	var cErofsFuseResults map[string]*benchResult
	t.Logf("Benchmarking C erofsfuse (%s)...", cErofsFuseBin)
	unmount = mountCErofsFuse(t, cErofsFuseBin, imagePath, blobdev, mntDir)
	cErofsFuseResults = runBenchmarks(t, fioBin, mntDir)
	unmount()

	printResultTable(t, leptonFSResults, cErofsFuseResults)
}

// runBenchmarks executes the full I/O and metadata benchmark suite against
// mntDir and returns the per-benchmark results keyed by name.
func runBenchmarks(t *testing.T, fioBin, mntDir string) map[string]*benchResult {
	largeFile := filepath.Join(mntDir, "large/file_0.bin")
	require.FileExists(t, largeFile)

	fioRuntime := texture.GetEnvAsInt("LEPTONFS_PERF_FIO_RUNTIME", 20)
	fioSeqNumjobs := texture.GetEnvAsInt("LEPTONFS_PERF_FIO_SEQ_NUMJOBS", 4)
	fioRandNumjobs := texture.GetEnvAsInt("LEPTONFS_PERF_FIO_RAND_NUMJOBS", 1)
	results := make(map[string]*benchResult)

	dropCaches(t)
	results["seq_read_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read", "--filename=" + largeFile,
		"--rw=read", "--bs=128k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["rand_read_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read", "--filename=" + largeFile,
		"--rw=randread", "--bs=128k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["seq_read_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4k", "--filename=" + largeFile,
		"--rw=read", "--bs=4k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["rand_read_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4k", "--filename=" + largeFile,
		"--rw=randread", "--bs=4k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	dropCaches(t)
	results["seq_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + largeFile,
		"--rw=read", "--bs=128k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["rand_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + largeFile,
		"--rw=randread", "--bs=128k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["seq_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + largeFile,
		"--rw=read", "--bs=4k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["rand_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + largeFile,
		"--rw=randread", "--bs=4k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["stat"] = benchStat(t, filepath.Join(mntDir, "small"))

	dropCaches(t)
	results["readdir"] = benchReaddir(t, filepath.Join(mntDir, "dirs"))
	return results
}

// benchStat repeatedly stats every file in dir for the configured metadata duration and
// reports the achieved ops/s and latency.
func benchStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(texture.GetEnvAsInt("LEPTONFS_PERF_META_SECS", 5)) * time.Second

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
	metaDuration := time.Duration(texture.GetEnvAsInt("LEPTONFS_PERF_READDIR_META_SECS", 5)) * time.Second
	passesPerDir := texture.GetEnvAsInt("LEPTONFS_PERF_READDIR_PASSES_PER_DIR", 8)

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

// benchResult is the per-job summary extracted from a benchmark run.
type benchResult struct {
	// A short name identifying the benchmark, e.g. "seq_read_128k".
	Name string

	// Throughput in MB/s.
	ReadBW float64

	// // I/O operations per second.
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

func printResultTable(t *testing.T, lepton, erofsfuse map[string]*benchResult) {
	type row struct {
		label         string
		key           string
		unit          string
		lowerIsBetter bool
		get           func(r *benchResult) float64
	}

	bw := func(r *benchResult) float64 { return r.ReadBW }
	iops := func(r *benchResult) float64 { return r.ReadIOPS }
	lat := func(r *benchResult) float64 { return r.ReadLat }
	rows := []row{
		{"Sequential Read (128K)", "seq_read_128k", "MiB/s", false, bw},
		{"Random Read (128K)", "rand_read_128k", "MiB/s", false, bw},
		{"Sequential Read (4K)", "seq_read_4k", "MiB/s", false, bw},
		{"Random Read (4K)", "rand_read_4k", "IOPS", false, iops},
		{"Random Read (4K) Lat", "rand_read_4k", "µs", true, lat},
		{"Seq Read 4-thread (128K)", "seq_read_4t_128k", "MiB/s", false, bw},
		{"Rand Read 4-thread (128K)", "rand_read_4t_128k", "MiB/s", false, bw},
		{"Seq Read 4-thread (4K)", "seq_read_4t_4k", "MiB/s", false, bw},
		{"Rand Read 4-thread (4K)", "rand_read_4t_4k", "MiB/s", false, bw},
		{"Stat", "stat", "IOPS", false, iops},
		{"Stat Latency", "stat", "µs", true, lat},
		{"Readdir", "readdir", "IOPS", false, iops},
		{"Readdir Latency", "readdir", "µs", true, lat},
	}

	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.Style().Options.SeparateRows = false
	tw.AppendHeader(table.Row{"Name", "Lepton", "erofsfuse"})
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Align: text.AlignLeft},
		{Number: 2, Align: text.AlignRight},
		{Number: 3, Align: text.AlignRight},
	})

	for _, r := range rows {
		lr := lepton[r.key]
		er := erofsfuse[r.key]
		if lr == nil || er == nil {
			continue
		}

		tw.AppendRow(table.Row{
			r.label,
			fmt.Sprintf("%.1f %s", r.get(lr), r.unit),
			fmt.Sprintf("%.1f %s", r.get(er), r.unit),
		})
	}

	t.Log("Performance Comparison\n" + tw.Render())
}
