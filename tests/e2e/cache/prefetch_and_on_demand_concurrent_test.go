package cache

import (
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// TestPrefetchAndOnDemandConcurrent runs a prefetching daemon against an
// on-demand one on one cache: neither may deadlock and both read the right
// bytes, including groups the other daemon filled.
func TestPrefetchAndOnDemandConcurrent(t *testing.T) {
	t.Parallel()
	w := setup(t)
	cacheDir := newCache(t)
	prefetcher := mountOn(t, w.image1, cacheDir, prefetchAll)
	reader := mountOn(t, w.image1, cacheDir)

	mustReadConcurrently(t, []*mount.Mounted{prefetcher, reader}, "shared.bin", w.want["shared.bin"])

	// Nobody reads file1.bin, so its blob is only filled by the prefetch.
	prefetcher.Daemon.WaitFor(t, 60*time.Second, "prefetch progress", func() bool {
		return metric(t, prefetcher, prefetchFill) > 0
	})
	waitAllReady(t, cacheDir, w.keyA, w.keyB)
	// The reader now gets groups another daemon filled.
	mustRead(t, reader.Path("shared.bin"), w.want["shared.bin"])
	mustRead(t, reader.Path("file1.bin"), w.want["file1.bin"])
}
