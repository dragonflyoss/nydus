//go:build manual

package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// benchResult is the summary of one benchmark job.
type benchResult struct {
	// Name identifies the benchmark, e.g. "seq_read_128k".
	Name string
	// ReadBW is the throughput in MiB/s.
	ReadBW   float64
	ReadIOPS float64
	// ReadLat is the mean latency in microseconds.
	ReadLat float64
}

// warmRow is a steady-state row of the table.
type warmRow struct {
	label, key, unit string
	get              func(r *benchResult) float64
}

func bandwidth(r *benchResult) float64 { return r.ReadBW }
func iops(r *benchResult) float64      { return r.ReadIOPS }
func latency(r *benchResult) float64   { return r.ReadLat }

var warmRows = []warmRow{
	{"Seq Read BW (128K)", "seq_read_128k", "MiB/s", bandwidth},
	{"Rand Read BW (128K)", "rand_read_128k", "MiB/s", bandwidth},
	{"Seq Read BW (4K)", "seq_read_4k", "MiB/s", bandwidth},
	{"Rand Read IOPS (4K)", "rand_read_4k", "IOPS", iops},
	{"Rand Read Lat (4K)", "rand_read_4k", "µs", latency},
	{"Seq 4t BW (128K)", "seq_read_4t_128k", "MiB/s", bandwidth},
	{"Rand 4t BW (128K)", "rand_read_4t_128k", "MiB/s", bandwidth},
	{"Seq 4t BW (4K)", "seq_read_4t_4k", "MiB/s", bandwidth},
	{"Rand 4t BW (4K)", "rand_read_4t_4k", "MiB/s", bandwidth},
	{"Stat IOPS", "stat", "IOPS", iops},
	{"Stat Latency", "stat", "µs", latency},
	{"Readdir IOPS", "readdir", "IOPS", iops},
	{"Readdir Latency", "readdir", "µs", latency},
	{"Listxattr IOPS", "listxattr", "IOPS", iops},
	{"Listxattr Latency", "listxattr", "µs", latency},
	{"Getxattr IOPS", "getxattr", "IOPS", iops},
	{"Getxattr Latency", "getxattr", "µs", latency},
	{"Readdir+stat (ls -l) IOPS", "readdir_stat", "IOPS", iops},
	{"Readdir+stat (ls -l) Latency", "readdir_stat", "µs", latency},
}

// coldRandRead does one non-repeating pass of random 4K reads over a file
// this mode has never touched, so every I/O is an on-demand fetch. fio's
// random map keeps blocks from repeating, which keeps the page cache out of
// the measurement.
func coldRandRead(t *testing.T, fio, file string) (float64, float64) {
	t.Helper()
	require.FileExists(t, file)
	ioSize := corpus.EnvInt("NYDUSFS_PERF_COLD_RAND_IO_SIZE", 16*1024*1024)
	res := runFio(t, fio, []string{
		"--name=cold_rand", "--filename=" + file,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--io_size=%d", ioSize),
		"--numjobs=1", "--readonly",
	})
	return res.ReadIOPS, res.ReadLat
}

// runWarmBenchmarks runs the steady-state I/O and metadata suite. The page
// cache is dropped before each fio job, and every job passes
// --invalidate=0: fio's default fadvises the file out of the page cache at
// job start, and cache state must be controlled by dropCaches alone.
func runWarmBenchmarks(t *testing.T, fio, targetFile, statDir, readdirDir string) map[string]*benchResult {
	t.Helper()
	require.FileExists(t, targetFile)
	runtime := fmt.Sprintf("--runtime=%d", corpus.EnvInt("NYDUSFS_PERF_FIO_RUNTIME", 8))
	seqJobs := fmt.Sprintf("--numjobs=%d", corpus.EnvInt("NYDUSFS_PERF_FIO_SEQ_NUMJOBS", 4))
	randJobs := fmt.Sprintf("--numjobs=%d", corpus.EnvInt("NYDUSFS_PERF_FIO_RAND_NUMJOBS", 4))
	job := func(name, rw, bs, numjobs string, extra ...string) []string {
		return append([]string{
			"--name=" + name, "--filename=" + targetFile,
			"--rw=" + rw, "--bs=" + bs, "--direct=0", "--invalidate=0",
			numjobs, runtime, "--ramp_time=2", "--time_based", "--readonly",
		}, extra...)
	}

	results := map[string]*benchResult{}
	for _, j := range []struct {
		key  string
		args []string
	}{
		{"seq_read_128k", job("seq_read", "read", "128k", "--numjobs=1")},
		{"rand_read_128k", job("rand_read", "randread", "128k", "--numjobs=1")},
		{"seq_read_4k", job("seq_read_4k", "read", "4k", "--numjobs=1")},
		{"rand_read_4k", job("rand_read_4k", "randread", "4k", "--numjobs=1")},
		{"seq_read_4t_128k", job("seq_read_4t", "read", "128k", seqJobs, "--group_reporting")},
		{"rand_read_4t_128k", job("rand_read_4t", "randread", "128k", randJobs, "--group_reporting")},
		{"seq_read_4t_4k", job("seq_read_4t", "read", "4k", seqJobs, "--group_reporting")},
		{"rand_read_4t_4k", job("rand_read_4t", "randread", "4k", randJobs, "--group_reporting")},
	} {
		dropCaches(t)
		results[j.key] = runFio(t, fio, j.args)
	}

	dropCaches(t)
	results["stat"] = benchStat(t, statDir)
	dropCaches(t)
	results["readdir"] = benchReaddir(t, readdirDir)
	return results
}

// filesUnder lists the non-directories under dir.
func filesUnder(dir string) []string {
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// repeat calls op for the metadata duration in key and reports the rate of
// the ops it counts.
func repeat(name, key string, op func() int) *benchResult {
	duration := time.Duration(corpus.EnvInt(key, 3)) * time.Second
	ops := 0
	start := time.Now()
	for deadline := start.Add(duration); time.Now().Before(deadline); {
		ops += op()
	}
	elapsed := time.Since(start).Seconds()
	return &benchResult{
		Name:     name,
		ReadIOPS: float64(ops) / elapsed,
		ReadLat:  elapsed / float64(ops) * 1e6,
	}
}

// benchStat stats every file in dir, over and over.
func benchStat(t *testing.T, dir string) *benchResult {
	t.Helper()
	files := filesUnder(dir)
	require.NotEmpty(t, files)
	return repeat("stat", "NYDUSFS_PERF_META_SECS", func() int {
		for _, f := range files {
			_, _ = os.Stat(f)
		}
		return len(files)
	})
}

// benchReaddir reads every subdirectory of dir, over and over.
func benchReaddir(t *testing.T, dir string) *benchResult {
	t.Helper()
	passes := corpus.EnvInt("NYDUSFS_PERF_READDIR_PASSES_PER_DIR", 8)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(dir, entry.Name()))
		}
	}
	require.NotEmpty(t, dirs)
	return repeat("readdir", "NYDUSFS_PERF_READDIR_META_SECS", func() int {
		for _, d := range dirs {
			for range passes {
				_, _ = os.ReadDir(d)
			}
		}
		return len(dirs) * passes
	})
}

// addMetaBenchmarks adds the listxattr, getxattr and readdir+stat
// benchmarks to results.
func addMetaBenchmarks(t *testing.T, results map[string]*benchResult, xattrDir, xattrName, statDir string) {
	t.Helper()
	if files := filesUnder(xattrDir); len(files) > 0 {
		list := make([]byte, 512)
		results["listxattr"] = repeat("listxattr", "NYDUSFS_PERF_META_SECS", func() int {
			for _, f := range files {
				_, _ = unix.Listxattr(f, list)
			}
			return len(files)
		})
		value := make([]byte, 256)
		results["getxattr"] = repeat("getxattr", "NYDUSFS_PERF_META_SECS", func() int {
			for _, f := range files {
				_, _ = unix.Getxattr(f, xattrName, value)
			}
			return len(files)
		})
	}

	// One op is an `ls -l` of statDir: readdir, then an lstat per entry.
	entries, err := os.ReadDir(statDir)
	require.NoError(t, err)
	if len(entries) > 0 {
		results["readdir_stat"] = repeat("readdir_stat", "NYDUSFS_PERF_META_SECS", func() int {
			ents, _ := os.ReadDir(statDir)
			for _, ent := range ents {
				_, _ = os.Lstat(filepath.Join(statDir, ent.Name()))
			}
			return 1
		})
	}
}

// fioJSON mirrors the part of fio's JSON output the benchmarks read.
type fioJSON struct {
	Jobs []struct {
		Jobname string `json:"jobname"`
		Read    struct {
			Bw    float64 `json:"bw"` // KiB/s
			Iops  float64 `json:"iops"`
			LatNs struct {
				Mean float64 `json:"mean"`
			} `json:"lat_ns"`
		} `json:"read"`
	} `json:"jobs"`
}

// runFio runs one fio job and returns its summary.
func runFio(t *testing.T, fio string, args []string) *benchResult {
	t.Helper()
	out, err := exec.Command(fio, append([]string{"--output-format=json"}, args...)...).CombinedOutput()
	require.NoError(t, err, "fio failed: %s", out)
	var result fioJSON
	require.NoError(t, json.Unmarshal(out, &result))
	require.NotEmpty(t, result.Jobs)
	job := result.Jobs[0]
	return &benchResult{
		Name:     job.Jobname,
		ReadBW:   job.Read.Bw / 1024,
		ReadIOPS: job.Read.Iops,
		ReadLat:  job.Read.LatNs.Mean / 1000,
	}
}
