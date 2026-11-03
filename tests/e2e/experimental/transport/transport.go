// Package transport holds the dataset and the test bodies the experimental
// transport suites share: an image served from an in-process registry, so a
// test can count backend fetches, and the checks every transport must pass
// on it.
package transport

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
)

const (
	// LargeFile is the path of the dataset's 64MiB file, the one read in
	// ranges.
	LargeFile = "large.bin"
	largeSize = 64 << 20
	manyFiles = 48

	concurrencyTimeout = 2 * time.Minute
)

var transportFailure = regexp.MustCompile(`nbd: (invalid request magic|read .* failed:|read length .* exceeds cap|unsupported request type)|fanotify: (immediate deny|fstat event fd failed|ready-range lookup failed|denying and skipping unusable event)|unknown event fd|InvalidRange|fanotify fetch (backend failure|worker panicked)`)

// expectHealthy fails t when the daemon logged protocol errors, failed
// reads or denied fanotify events.
func expectHealthy(t testing.TB, d *mount.Daemon) {
	t.Helper()
	assert.Empty(t, transportFailure.FindAllString(d.Log(), -1))
}

// manyName is the name of the i-th small file of the fan.
func manyName(i int) string { return fmt.Sprintf("many/f%d.bin", i) }

// Serve builds the dataset image and pushes its blob to a registry under
// repo. The dataset is specific to these tests, so it is built in the
// test's own directory rather than taken from the fixture cache.
func Serve(t testing.TB, repo string) *registry.Served {
	t.Helper()
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "source")
	c := corpus.New(t, src)
	c.CreateFile(t, "hello.txt", []byte("hello nydus\n"))
	c.CreateFile(t, "subdir/nested.txt", []byte("nested file content\n"))
	c.CreateFile(t, "data.bin", seeded("data.bin", 100*4096))
	c.CreateFile(t, LargeFile, seeded(LargeFile, largeSize))

	for i := 1; i <= manyFiles; i++ {
		c.CreateFile(t, manyName(i), seeded(manyName(i), (4+(i*7)%20)*4096))
	}

	return registry.Serve(t, fixture.BuildImage(t, dir, src, fixture.MustLayout(t, "zstd")), repo)
}

// seeded returns size pseudo-random bytes seeded by the file name, so every
// file differs yet the dataset is reproducible.
func seeded(name string, size int) []byte {
	sum := sha256.Sum256([]byte(name))
	return corpus.Bytes(binary.LittleEndian.Uint64(sum[:]), size)
}

// Concurrency checks that many readers of distinct files and of distinct
// ranges of one large file all see the source bytes, and that the daemon
// stays healthy under them.
func Concurrency(t *testing.T, a mount.Adapter, repo string) {
	a.Require(t)
	s := Serve(t, repo)
	m := s.Mount(t, a, mount.Options{})
	src, mnt := s.Image.Source, m.Root

	var wg sync.WaitGroup
	offsets := []int64{0, 4, 8, 8, 12, 16, 16, 20}
	errs := make(chan error, manyFiles+len(offsets))

	for i := 1; i <= manyFiles; i++ {
		wg.Go(func() {
			errs <- fstest.SameFile(filepath.Join(src, manyName(i)), filepath.Join(mnt, manyName(i)))
		})
	}

	for _, mib := range offsets {
		wg.Go(func() {
			errs <- fstest.SameRange(filepath.Join(src, LargeFile), filepath.Join(mnt, LargeFile), mib<<20, 2<<20)
		})
	}

	done := make(chan struct{})

	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:

	case <-time.After(concurrencyTimeout):
		t.Fatalf("concurrent readers still blocked after %s", concurrencyTimeout)
	}

	close(errs)

	for err := range errs {
		assert.NoError(t, err)
	}

	if !assert.True(t, m.Daemon.Alive()) {
		t.FailNow()
	}

	expectHealthy(t, m.Daemon)
}

// Persistence checks that a second mount on a filled cache reads the whole
// image without fetching from the registry or growing the cache.
func Persistence(t *testing.T, a mount.Adapter, repo string) {
	a.Require(t)
	s := Serve(t, repo)
	cache := filepath.Join(env.WorkDir(t), "cache")

	first := s.Mount(t, a, mount.Options{CacheDir: cache})
	mount.ReadAll(t, first.Root)
	first.Unmount()
	used, gets := mount.CacheUsed(cache), s.BlobGets()
	if !assert.Positive(t, gets) {
		t.FailNow()
	}

	second := s.Mount(t, a, mount.Options{CacheDir: cache})
	fstest.VerifyMount(t, second.Root, s.Image.Want, s.Image.Compare())
	assert.Equal(t, gets, s.BlobGets())
	assert.Less(t, mount.CacheUsed(cache)-used, int64(1<<20))
}

// DemandPaging checks that the cache only grows with what is read: nothing
// for metadata, bounded ranges for partial reads, everything for a full
// read, and nothing again for a warm re-read. startup checks the transport's
// own readiness evidence before any read.
func DemandPaging(t *testing.T, a mount.Adapter, repo string, startup func(t *testing.T, m *mount.Mounted, cache string)) {
	a.Require(t)
	s := Serve(t, repo)
	cache := filepath.Join(env.WorkDir(t), "cache")
	m := s.Mount(t, a, mount.Options{CacheDir: cache})
	src, mnt := s.Image.Source, m.Root
	large := func(dir string) string { return filepath.Join(dir, LargeFile) }

	t.Run("Startup", func(t *testing.T) {
		startup(t, m, cache)
	})

	t.Run("Metadata", func(t *testing.T) {
		before := mount.CacheUsed(cache)

		for _, dir := range []string{mnt, filepath.Join(mnt, "subdir"), filepath.Join(mnt, "many")} {
			entries, err := os.ReadDir(dir)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			for _, e := range entries {
				_, err := os.Lstat(filepath.Join(dir, e.Name()))
				assert.NoError(t, err)
			}
		}

		assert.Less(t, mount.CacheUsed(cache)-before, int64(1<<20))
	})

	t.Run("PartialReads", func(t *testing.T) {
		before := mount.CacheUsed(cache)

		for _, mib := range []int64{1, 17, 40, 63} {
			assert.NoError(t, fstest.SameRange(large(src), large(mnt), mib<<20, 1<<20))
		}

		after := mount.CacheUsed(cache)
		if !assert.Less(t, after-before, int64(24<<20)) {
			t.FailNow()
		}

		assert.Less(t, after, int64(48<<20))
	})

	t.Run("FullRead", func(t *testing.T) {
		before := mount.CacheUsed(cache)
		fstest.VerifyMount(t, mnt, s.Image.Want, s.Image.Compare())
		after := mount.CacheUsed(cache)
		if !assert.Greater(t, after, before) {
			t.FailNow()
		}

		assert.Greater(t, after, int64(40<<20))
	})

	t.Run("WarmReread", func(t *testing.T) {
		if !assert.NoError(t, fstest.SameFile(large(src), large(mnt))) {
			t.FailNow()
		}

		before, gets := mount.CacheUsed(cache), s.BlobGets()
		fstest.DropPageCache(t, large(mnt))

		if !assert.NoError(t, fstest.SameFile(large(src), large(mnt))) {
			t.FailNow()
		}

		assert.Less(t, mount.CacheUsed(cache)-before, int64(1<<20))
		assert.Equal(t, gets, s.BlobGets())
	})

	t.Run("Health", func(t *testing.T) {
		expectHealthy(t, m.Daemon)
	})
}
