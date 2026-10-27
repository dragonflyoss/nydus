package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"golang.org/x/sys/unix"
)

// TestENOSPC serves an image whose decoded data (96MiB) exceeds the 64MiB
// tmpfs holding the cache. Once the cache cannot take another chunk group,
// a read fails (EIO, or ENOSPC passed through) rather than returning bytes
// that never made it into the cache, and the daemon keeps serving: nothing
// it already cached reads back wrong.
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
			m := mount.Mount(t, a, img, mount.Options{CacheDir: cache})
			expectCorrect(t, readWithin(t, m.Root, files[0], time.Minute))

			// The second pass mixes groups cached by the first with groups
			// that no longer fit.
			for pass := 1; pass <= 2; pass++ {
				ok, failed := 0, 0
				for _, r := range readParallel(t, m.Root, files, time.Minute) {
					expectNotWrong(t, r)
					switch {
					case r.Err == nil:
						ok++
					case isErrno(r.Err, syscall.EIO, syscall.ENOSPC):
						failed++
					default:
						t.Errorf("want the right bytes, EIO or ENOSPC: %s", r)
					}
				}
				t.Logf("pass %d: %d files ok, %d failed; %s free in the cache", pass, ok, failed, free(t, cache))
				if failed == 0 {
					t.Errorf("pass %d never exercised a failed cache write", pass)
				}
				if ok == 0 {
					t.Errorf("pass %d could not read the file cached before ENOSPC", pass)
				}
				if failures := m.API.Metrics(t).Sum("nydus_cache_write_failure_total", `reason="io"`); failures == 0 {
					t.Error("ENOSPC did not increment cache I/O failures")
				}
				if !m.Daemon.Alive() {
					t.Fatalf("the daemon died with its cache full (exit code %d)", m.Daemon.ExitCode())
				}
			}
		})
	}
}

// largeImage builds an image of n files of size random bytes each, which
// no compressor shrinks, and returns it with its files.
func largeImage(t *testing.T, n, size int) (fixture.Image, []dataFile) {
	t.Helper()
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("create %s: %v", src, err)
	}
	rng := rand.NewChaCha8([32]byte{'e', 'n', 'o', 's', 'p', 'c'})
	buf := make([]byte, size)
	var files []dataFile
	for i := range n {
		rel := fmt.Sprintf("big%d", i)
		_, _ = rng.Read(buf)
		if err := os.WriteFile(filepath.Join(src, rel), buf, 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		sum := sha256.Sum256(buf)
		files = append(files, dataFile{Rel: rel, Size: int64(size), SHA256: hex.EncodeToString(sum[:])})
	}

	layout, err := fixture.LayoutByName("zstd")
	if err != nil {
		t.Fatalf("%v", err)
	}
	bootstrap := filepath.Join(dir, "image.bootstrap")
	blobDir := filepath.Join(dir, "blobs")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, src, layout)
	return fixture.Image{
		Name:      "enospc-zstd",
		Layout:    layout,
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     []string{blob},
		Source:    src,
	}, files
}

// mountTmpfs mounts a tmpfs of size on dir until the test ends. Called
// before mount.Mount, its cleanup runs after the daemon's teardown.
func mountTmpfs(t *testing.T, dir, size string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "size="+size); err != nil {
		t.Fatalf("mount tmpfs on %s: %v", dir, err)
	}
	t.Cleanup(func() { mount.Unmount(dir) })
}

// free reports the space left on the filesystem holding dir.
func free(t *testing.T, dir string) string {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatalf("statfs %s: %v", dir, err)
	}
	return fmt.Sprintf("%.1fMiB", float64(st.Bavail*uint64(st.Bsize))/(1<<20))
}

// readParallel reads every file through root at once and fails t if the
// reads have not all returned within timeout.
func readParallel(t *testing.T, root string, files []dataFile, timeout time.Duration) []result {
	t.Helper()
	ch := make(chan result, len(files))
	start := time.Now()
	for _, f := range files {
		go func() {
			sum, err := hashRead(filepath.Join(root, f.Rel))
			ch <- result{File: f, Err: err, Wrong: err == nil && sum != f.SHA256, Elapsed: time.Since(start)}
		}()
	}
	deadline := time.After(timeout)
	var out []result
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
