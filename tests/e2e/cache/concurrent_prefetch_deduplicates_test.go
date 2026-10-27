package cache

import "testing"

// TestConcurrentPrefetchDeduplicates checks the per-blob prefetch lock: of
// several daemons prefetching one cold cache, only one streams each blob.
func TestConcurrentPrefetchDeduplicates(t *testing.T) {
	t.Parallel()
	w := setup(t)

	soloCache := newCache(t)
	solo := mountOn(t, w.image1, soloCache, prefetchAll)
	waitAllReady(t, soloCache, w.keyA, w.keyB)
	soloFill := settled(t, "solo prefetch", func() float64 { return metric(t, solo, prefetchFill) })

	sharedCache := newCache(t)
	mounts := mountN(t, procs, w.image1, sharedCache, prefetchAll)
	waitAllReady(t, sharedCache, w.keyA, w.keyB)
	total := settled(t, "shared prefetch", func() float64 { return sumMetric(t, mounts, prefetchFill) })

	t.Logf("prefetch amplification: solo %.0f groups, %d daemons %.0f groups", soloFill, procs, total)
	if total > soloFill*1.5 {
		t.Errorf("%d daemons prefetched %.0f groups, solo %.0f: the prefetch lock does not keep the others from refetching",
			procs, total, soloFill)
	}
	for i, m := range mounts {
		mustRead(t, m.Path("shared.bin"), w.want["shared.bin"])
		if i == 0 {
			mustRead(t, m.Path("file1.bin"), w.want["file1.bin"])
		}
	}
}
