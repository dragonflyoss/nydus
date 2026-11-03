package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestENOSPC(t *testing.T) {
	t.Parallel()
	env.RequireRoot(t)
	img, files := largeImage(t, 6, 16<<20)

	for _, a := range adapters {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			a.Require(t)
			cache := filepath.Join(env.WorkDir(t), "cache")
			mountTmpfs(t, cache, "64m")
			m := img.mount(t, a, mount.Options{CacheDir: cache})
			files[0].readWithin(t, m.Root, time.Minute).expectCorrect(t)

			for pass := 1; pass <= 2; pass++ {
				ok, failed := 0, 0
				before := m.API.Metrics(t).Sum("nydus_cache_write_failure_total", `reason="io"`)

				for _, r := range readParallel(t, m.Root, files, time.Minute) {
					r.expectNotWrong(t)

					if r.file == files[0] {
						r.expectCorrect(t)
					}

					if r.err == nil {
						ok++
						continue
					}

					var errno unix.Errno
					if !assert.ErrorAs(t, r.err, &errno) {
						t.FailNow()
					}

					assert.Contains(t, []unix.Errno{unix.EIO, unix.ENOSPC}, errno)
					failed++
				}

				t.Logf("pass %d: %d files ok, %d failed; %s free in the cache", pass, ok, failed, free(t, cache))
				assert.NotZero(t, failed)
				assert.NotZero(t, ok)
				assert.Greater(t, m.API.Metrics(t).Sum("nydus_cache_write_failure_total", `reason="io"`), before)

				if !assert.True(t, m.Daemon.Alive()) {
					t.FailNow()
				}
			}
		})
	}
}

func largeImage(t *testing.T, n, size int) (image, []dataFile) {
	t.Helper()
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); !assert.NoError(t, err) {
		t.FailNow()
	}

	var files []dataFile

	for i := range n {
		rel := fmt.Sprintf("big%d", i)
		buf := corpus.Bytes(uint64(i), size)
		if err := os.WriteFile(filepath.Join(src, rel), buf, 0o644); !assert.NoError(t, err) {
			t.FailNow()
		}

		sum := sha256.Sum256(buf)
		files = append(files, dataFile{rel: rel, size: int64(size), sha256: hex.EncodeToString(sum[:])})
	}

	return image{fixture.BuildImage(t, dir, src, fixture.MustLayout(t, "zstd"))}, files
}

func mountTmpfs(t *testing.T, dir, size string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); !assert.NoError(t, err) {
		t.FailNow()
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "size="+size); !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { mount.Unmount(dir) })
}

func free(t *testing.T, dir string) string {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); !assert.NoError(t, err) {
		t.FailNow()
	}

	return fmt.Sprintf("%.1fMiB", float64(st.Bavail*uint64(st.Bsize))/(1<<20))
}

func readParallel(t *testing.T, root string, files []dataFile, timeout time.Duration) []readResult {
	t.Helper()
	ch := make(chan readResult, len(files))
	start := time.Now()

	for _, f := range files {
		go func() {
			sum, err := fstest.HashFileCold(filepath.Join(root, f.rel))
			ch <- readResult{file: f, err: err, wrong: err == nil && sum != f.sha256, elapsed: time.Since(start)}
		}()
	}

	deadline := time.After(timeout)
	var out []readResult

	for range files {
		select {
		case r := <-ch:
			out = append(out, r)

		case <-deadline:
			t.Fatalf("%d of %d reads did not return within %s: the daemon hangs", len(files)-len(out), len(files), timeout)
		}
	}

	return out
}
