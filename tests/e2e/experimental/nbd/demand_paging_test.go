package nbd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestDemandPaging follows one cold mount through its life and checks, by
// the bytes allocated in the sparse cache and the blobs fetched from the
// registry, that data is fetched when it is read and only then: metadata
// comes from the bootstrap, a partial read pulls a bounded range, a full
// read fills the cache and a warm re-read fetches nothing. Every byte read
// is compared with the source.
func TestDemandPaging(t *testing.T) {
	t.Parallel()
	NBD{}.Require(t)
	s := serveDataset(t)
	cache := filepath.Join(env.WorkDir(t), "cache")
	m := s.mount(t, cache)
	src, mnt := s.img.Source, m.Root

	t.Run("Startup", func(t *testing.T) {
		log := m.Daemon.Log()
		require.Contains(t, log, "nbd service attached to")
		require.Contains(t, log, "mounted ")
		// Before any file is read, only what attaching and mounting touch
		// is fetched: the device head and tail the kernel scans, each
		// rounded up to the fetch-size cell around it. Bound it well below
		// the 64MiB blob rather than at zero.
		for _, f := range cacheFiles(cache) {
			require.Less(t, allocated(f), int64(16<<20), "%s filled before any file read", filepath.Base(f))
		}
	})

	t.Run("Metadata", func(t *testing.T) {
		before := cacheUsed(cache)
		for _, dir := range []string{mnt, filepath.Join(mnt, "subdir"), filepath.Join(mnt, "many")} {
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			for _, e := range entries {
				_, err := os.Lstat(filepath.Join(dir, e.Name()))
				require.NoError(t, err)
			}
		}
		require.Less(t, cacheUsed(cache)-before, int64(1<<20), "listing and stat filled the blob cache")
	})

	t.Run("PartialReads", func(t *testing.T) {
		before := cacheUsed(cache)
		for _, mib := range []int64{1, 17, 40, 63} {
			require.NoError(t, sameRange(filepath.Join(src, largeFile), filepath.Join(mnt, largeFile), mib<<20, 1<<20))
		}
		// 4MiB read; chunk and fetch-size rounding amplify it, a whole-blob
		// pull per read would not stay below these.
		after := cacheUsed(cache)
		require.Less(t, after-before, int64(24<<20), "partial reads pulled more than bounded ranges")
		require.Less(t, after, int64(48<<20), "cache near full after partial reads")
	})

	t.Run("FullRead", func(t *testing.T) {
		before := cacheUsed(cache)
		oracle.VerifyMount(t, mnt, s.img.Want, s.img.Compare())
		after := cacheUsed(cache)
		require.Greater(t, after, before, "reading the tree did not grow the cache")
		require.Greater(t, after, int64(40<<20), "cache not filled after reading every file")
	})

	t.Run("WarmReread", func(t *testing.T) {
		before, gets := cacheUsed(cache), s.blobGets()
		dropPageCache(t, filepath.Join(mnt, largeFile))
		require.NoError(t, sameFile(filepath.Join(src, largeFile), filepath.Join(mnt, largeFile)))
		require.Less(t, cacheUsed(cache)-before, int64(1<<20), "warm re-read allocated cache")
		require.Equal(t, gets, s.blobGets(), "warm re-read fetched from the backend")
	})

	t.Run("Health", func(t *testing.T) {
		requireHealthy(t, m.Daemon)
	})
}
