package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/integration/texture"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// TestPerf runs fio-based I/O benchmarks and Go-based metadata benchmarks
// against the Rust `nydus fuse`, optionally comparing the results with
// the C `erofsfuse` implementation.
//
// Activation:
//
//	NYDUSFS_RUN_PERF=1                     enable the test (off by default).
//	                                     (auto-detected when omitted).
//
// Tuning knobs (all optional):
//
//	NYDUSFS_PERF_LARGE_FILE_COUNT        Number of large files for read benchmarks (default 8).
//	NYDUSFS_PERF_LARGE_FILE_SIZE         Size of each large file (default 64MiB).
//	NYDUSFS_PERF_MEDIUM_FILE_COUNT       Number of medium files in the corpus (default 256).
//	NYDUSFS_PERF_MEDIUM_FILE             Size of each medium file (default 1Mib).
//	NYDUSFS_PERF_SMALL_FILE_COUNT        Number of small files for the stat benchmark (default 10000).
//	NYDUSFS_PERF_FIO_RUNTIME             Fio benchmark duration in seconds (default 20).
//	NYDUSFS_PERF_FIO_SEQ_NUMJOBS         Sequential-read multi-thread job count (default 4).
//	NYDUSFS_PERF_FIO_RAND_NUMJOBS        Random-read multi-thread job count (default 4).
//	NYDUSFS_PERF_READDIR_DIRS            Number of directories for the readdir corpus (default 128).
//	NYDUSFS_PERF_READDIR_FILES_PER_DIR   Files per directory for the readdir corpus (default 256).
//	NYDUSFS_PERF_READDIR_META_SECS       Metadata benchmark duration in seconds (default 5).
//	NYDUSFS_PERF_READDIR_PASSES_PER_DIR  Repeated os.ReadDir calls per directory per iteration (default 8).
func TestPerf(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}

	if os.Getenv("NYDUSFS_RUN_PERF") == "" {
		t.Skip("set NYDUSFS_RUN_PERF=1 to enable")
	}

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	imagePath := filepath.Join(tmpDir, "test.image")
	blobdev := filepath.Join(tmpDir, "test.blobdev")
	mntDir := filepath.Join(tmpDir, "mnt")

	// Ensure erofsfuse is built and available if we're going to benchmark it.
	setupCErofsfuse(t)
	fioBin := mustLookupFio(t)
	nydusBin := mustLookupExecutable(t, "nydus")
	cErofsFuseBin := mustLookupCErofsFuse(t)

	// Generate the performance corpus (~260 MiB by default).
	t.Log("Generating performance corpus...")
	texture.MakePerfCorpus(t, corpusDir)

	// Build the NydusFS image with 1 MiB chunks (a realistic chunk size).
	t.Log("Building NydusFS image (chunksize=1MiB)...")
	buildNydusFSImage(t, nydusBin, imagePath, blobdev, corpusDir, 1024*1024)

	// Benchmark the Rust nydus FUSE implementation.
	t.Log("Benchmarking nydus...")
	unmount := mountNydus(t, nydusBin, imagePath, blobdev, mntDir)
	targetFile := filepath.Join(mntDir, "large/file_0.bin")
	statDir := filepath.Join(mntDir, "small")
	readdirDir := filepath.Join(mntDir, "dirs")
	nydusFSResults := runBenchmarks(t, fioBin, targetFile, statDir, readdirDir, true)
	unmount()

	// Benchmark the C erofsfuse implementation for comparison.
	var cErofsFuseResults map[string]*benchResult
	t.Logf("Benchmarking C erofsfuse (%s)...", cErofsFuseBin)
	unmount = mountCErofsFuse(t, cErofsFuseBin, imagePath, mntDir, blobdev)
	cErofsFuseResults = runBenchmarks(t, fioBin, targetFile, statDir, readdirDir, true)
	unmount()

	printResultTable(t, nydusFSResults, cErofsFuseResults)
}

func printResultTable(t *testing.T, nydus, erofsfuse map[string]*benchResult) {
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
	tw.AppendHeader(table.Row{"Name", "Nydus", "erofsfuse"})
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Align: text.AlignLeft},
		{Number: 2, Align: text.AlignRight},
		{Number: 3, Align: text.AlignRight},
	})

	for _, r := range rows {
		lr := nydus[r.key]
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
