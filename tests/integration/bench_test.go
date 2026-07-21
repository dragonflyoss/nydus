package integration

// Shared benchmark suite reused by TestPerf (nydus fuse vs C erofsfuse) and
// TestFanotifyPerf (fanotify vs fuse): the fio I/O jobs, the Go metadata
// benchmarks, and the result types they produce.

import (
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

	"github.com/dragonflyoss/nydus/tests/integration/texture"
	"github.com/stretchr/testify/require"
)

// runBenchmarks executes the full I/O and metadata benchmark suite and returns
// the per-benchmark results keyed by name. When cold is true, dropCaches is
// called before each fio job to force cache-miss reads; when false, the page
// cache is left intact for warm-cache measurements.
func runBenchmarks(t *testing.T, fioBin, targetFile, statDir, readdirDir string, cold bool) map[string]*benchResult {
	require.FileExists(t, targetFile)

	fioRuntime := texture.GetEnvAsInt("NYDUSFS_PERF_FIO_RUNTIME", 20)
	fioSeqNumjobs := texture.GetEnvAsInt("NYDUSFS_PERF_FIO_SEQ_NUMJOBS", 4)
	fioRandNumjobs := texture.GetEnvAsInt("NYDUSFS_PERF_FIO_RAND_NUMJOBS", 4)
	results := make(map[string]*benchResult)

	maybeDrop := func() {
		if cold {
			dropCaches(t)
		}
	}

	maybeDrop()
	results["seq_read_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read", "--filename=" + targetFile,
		"--rw=read", "--bs=128k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	maybeDrop()
	results["rand_read_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read", "--filename=" + targetFile,
		"--rw=randread", "--bs=128k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	maybeDrop()
	results["seq_read_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4k", "--filename=" + targetFile,
		"--rw=read", "--bs=4k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	maybeDrop()
	results["rand_read_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4k", "--filename=" + targetFile,
		"--rw=randread", "--bs=4k", "--direct=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based", "--readonly",
	})

	maybeDrop()
	results["seq_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + targetFile,
		"--rw=read", "--bs=128k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	maybeDrop()
	results["rand_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + targetFile,
		"--rw=randread", "--bs=128k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	maybeDrop()
	results["seq_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + targetFile,
		"--rw=read", "--bs=4k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	maybeDrop()
	results["rand_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + targetFile,
		"--rw=randread", "--bs=4k", "--direct=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--time_based",
		"--readonly", "--group_reporting",
	})

	maybeDrop()
	results["stat"] = benchStat(t, statDir)

	maybeDrop()
	results["readdir"] = benchReaddir(t, readdirDir)
	return results
}

// benchStat repeatedly stats every file in dir for the configured metadata duration and
// reports the achieved ops/s and latency.
func benchStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(texture.GetEnvAsInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

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
	metaDuration := time.Duration(texture.GetEnvAsInt("NYDUSFS_PERF_READDIR_META_SECS", 5)) * time.Second
	passesPerDir := texture.GetEnvAsInt("NYDUSFS_PERF_READDIR_PASSES_PER_DIR", 8)

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
// readdir+stat) and inserts their results into the provided map. These
// benchmarks run independently of dropCaches because they measure filesystem
// metadata path overhead (syscall round-trips), not page-cache data access.
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
	metaDuration := time.Duration(texture.GetEnvAsInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

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
	metaDuration := time.Duration(texture.GetEnvAsInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

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
	metaDuration := time.Duration(texture.GetEnvAsInt("NYDUSFS_PERF_META_SECS", 5)) * time.Second

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

// findXattrTargets walks the mount (capped at 5000 regular file probes) to
// locate the directory with the most xattr-bearing files and the most
// frequently occurring xattr name — used for listxattr/getxattr benchmarks.
// Returns ("", "") when no xattr-bearing files are found.
func findXattrTargets(t *testing.T, mnt string) (dir string, name string) {
	t.Helper()

	const maxProbes = 5000
	probed := 0
	dirCount := make(map[string]int)
	nameFreq := make(map[string]int)

	_ = filepath.Walk(mnt, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if probed >= maxProbes {
			return filepath.SkipAll
		}
		probed++

		// Fast probe: nil buffer to get required size.
		sz, err := syscall.Listxattr(path, nil)
		if err != nil || sz <= 0 {
			return nil
		}

		buf := make([]byte, sz)
		sz, err = syscall.Listxattr(path, buf)
		if err != nil || sz <= 0 {
			return nil
		}

		dirCount[filepath.Dir(path)]++

		// Parse null-separated xattr names.
		names := strings.Split(string(buf[:sz-1]), "\x00")
		for _, n := range names {
			if n != "" {
				nameFreq[n]++
			}
		}
		return nil
	})

	// Best directory.
	bestCount := 0
	for d, c := range dirCount {
		if c > bestCount {
			bestCount, dir = c, d
		}
	}

	// Best xattr name.
	bestFreq := 0
	for n, c := range nameFreq {
		if c > bestFreq {
			bestFreq, name = c, n
		}
	}

	return dir, name
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
