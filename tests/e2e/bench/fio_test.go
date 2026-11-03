package bench

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type fioResult struct {
	readBW   float64
	readIOPS float64
	readLat  float64
}

func coldRandRead(t testing.TB, fio, file string) (float64, float64) {
	t.Helper()
	if !assert.FileExists(t, file) {
		t.FailNow()
	}

	ioSize := env.Int(t, "NYDUS_E2E_BENCH_COLD_RAND_IO_SIZE", 16*1024*1024)

	res := runFio(t, fio, []string{
		"--name=cold_rand", "--filename=" + file,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--io_size=%d", ioSize),
		"--numjobs=1", "--readonly",
	})

	return res.readIOPS, res.readLat
}

func runWarmBenchmarks(t testing.TB, fio, targetFile, statDir, readdirDir string) map[string]*fioResult {
	t.Helper()
	if !assert.FileExists(t, targetFile) {
		t.FailNow()
	}

	runtime := fmt.Sprintf("--runtime=%d", env.Int(t, "NYDUS_E2E_BENCH_FIO_RUNTIME", 8))
	seqJobs := fmt.Sprintf("--numjobs=%d", env.Int(t, "NYDUS_E2E_BENCH_FIO_SEQ_NUMJOBS", 4))
	randJobs := fmt.Sprintf("--numjobs=%d", env.Int(t, "NYDUS_E2E_BENCH_FIO_RAND_NUMJOBS", 4))

	job := func(name, rw, bs, numjobs string, extra ...string) []string {
		return append([]string{
			"--name=" + name, "--filename=" + targetFile,
			"--rw=" + rw, "--bs=" + bs, "--direct=0", "--invalidate=0",
			numjobs, runtime, "--ramp_time=2", "--time_based", "--readonly",
		}, extra...)
	}

	results := map[string]*fioResult{}

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
	results["stat"] = measureStat(t, statDir)
	dropCaches(t)
	results["readdir"] = measureReaddir(t, readdirDir)

	return results
}

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

func repeat(t testing.TB, key string, op func() int) *fioResult {
	t.Helper()
	duration := time.Duration(env.Int(t, key, 3)) * time.Second
	ops := 0

	start := time.Now()
	for deadline := start.Add(duration); time.Now().Before(deadline); {
		ops += op()
	}

	elapsed := time.Since(start).Seconds()

	return &fioResult{
		readIOPS: float64(ops) / elapsed,
		readLat:  elapsed / float64(ops) * 1e6,
	}
}

func measureStat(t testing.TB, dir string) *fioResult {
	t.Helper()
	files := filesUnder(dir)
	if !assert.NotEmpty(t, files) {
		t.FailNow()
	}

	return repeat(t, "NYDUS_E2E_BENCH_META_SECS", func() int {
		for _, f := range files {
			_, _ = os.Stat(f)
		}

		return len(files)
	})
}

func measureReaddir(t testing.TB, dir string) *fioResult {
	t.Helper()
	passes := env.Int(t, "NYDUS_E2E_BENCH_READDIR_PASSES_PER_DIR", 8)
	entries, err := os.ReadDir(dir)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var dirs []string

	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(dir, entry.Name()))
		}
	}

	if !assert.NotEmpty(t, dirs) {
		t.FailNow()
	}

	return repeat(t, "NYDUS_E2E_BENCH_READDIR_META_SECS", func() int {
		for _, d := range dirs {
			for range passes {
				_, _ = os.ReadDir(d)
			}
		}

		return len(dirs) * passes
	})
}

func addMetaBenchmarks(t testing.TB, results map[string]*fioResult, xattrDir, xattrName, statDir string) {
	t.Helper()
	if files := filesUnder(xattrDir); len(files) > 0 {
		list := make([]byte, 512)

		results["listxattr"] = repeat(t, "NYDUS_E2E_BENCH_META_SECS", func() int {
			for _, f := range files {
				_, _ = unix.Listxattr(f, list)
			}

			return len(files)
		})

		value := make([]byte, 256)

		results["getxattr"] = repeat(t, "NYDUS_E2E_BENCH_META_SECS", func() int {
			for _, f := range files {
				_, _ = unix.Getxattr(f, xattrName, value)
			}

			return len(files)
		})
	}

	entries, err := os.ReadDir(statDir)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	if len(entries) > 0 {
		results["readdir_stat"] = repeat(t, "NYDUS_E2E_BENCH_META_SECS", func() int {
			ents, _ := os.ReadDir(statDir)
			for _, ent := range ents {
				_, _ = os.Lstat(filepath.Join(statDir, ent.Name()))
			}

			return 1
		})
	}
}

type fioJSON struct {
	Jobs []struct {
		Read struct {
			BW    float64 `json:"bw"`
			IOPS  float64 `json:"iops"`
			LatNs struct {
				Mean float64 `json:"mean"`
			} `json:"lat_ns"`
		} `json:"read"`
	} `json:"jobs"`
}

func runFio(t testing.TB, fio string, args []string) *fioResult {
	t.Helper()
	out, err := exec.Command(fio, append([]string{"--output-format=json"}, args...)...).Output()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		t.Fatalf("fio: %v\n%s", err, exitErr.Stderr)
	}
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var result fioJSON
	if !assert.NoError(t, json.Unmarshal(out, &result)) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, result.Jobs) {
		t.FailNow()
	}

	job := result.Jobs[0]

	return &fioResult{
		readBW:   job.Read.BW / 1024,
		readIOPS: job.Read.IOPS,
		readLat:  job.Read.LatNs.Mean / 1000,
	}
}
