package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConcurrentColdReadIsConsistent(t *testing.T) {
	t.Parallel()
	w := setup(t)
	mounts := newCache(t).mountN(t, peerCount, w.lowerImage)

	mounts.mustReadConcurrently(t, "shared.bin", w.want["shared.bin"])
	mounts.mustReadConcurrently(t, "lower.bin", w.want["lower.bin"])
}

func TestConcurrentColdReadAmplification(t *testing.T) {
	t.Parallel()
	w := setup(t)

	solo := newCache(t).mount(t, w.lowerImage)
	solo.mustRead(t, "shared.bin", w.want["shared.bin"])
	soloFill := solo.metric(t, ondemandFill)
	if !assert.Greater(t, soloFill, 1.0) {
		t.FailNow()
	}

	mounts := newCache(t).mountN(t, peerCount, w.lowerImage)
	mounts.mustReadConcurrently(t, "shared.bin", w.want["shared.bin"])
	total := mounts.sumMetric(t, ondemandFill)

	t.Logf("cold read amplification: solo %.0f groups, %d daemons %.0f groups (%.2fx)",
		soloFill, peerCount, total, total/soloFill)

	slack := max(2, soloFill/10)
	assert.LessOrEqual(t, total, soloFill+slack)
}

func TestConcurrentPrefetchDeduplicates(t *testing.T) {
	t.Parallel()
	w := setup(t)

	soloCache := newCache(t)
	solo := soloCache.mount(t, w.lowerImage, prefetchAll)
	soloCache.waitAllReady(t, w.lowerBlob, w.sharedBlob)
	soloFill := settled(t, func() (float64, error) { return solo.writes(prefetchFill) })

	sharedCache := newCache(t)
	mounts := sharedCache.mountN(t, peerCount, w.lowerImage, prefetchAll)
	sharedCache.waitAllReady(t, w.lowerBlob, w.sharedBlob)
	total := settled(t, func() (float64, error) { return mounts.sumWrites(prefetchFill) })

	t.Logf("prefetch amplification: solo %.0f groups, %d daemons %.0f groups", soloFill, peerCount, total)
	assert.LessOrEqual(t, total, soloFill*1.5)

	for i, m := range mounts {
		m.mustRead(t, "shared.bin", w.want["shared.bin"])

		if i == 0 {
			m.mustRead(t, "lower.bin", w.want["lower.bin"])
		}
	}
}

func TestPrefetchAndOnDemandConcurrent(t *testing.T) {
	t.Parallel()
	w := setup(t)
	cache := newCache(t)
	prefetcher := cache.mount(t, w.lowerImage, prefetchAll)
	reader := cache.mount(t, w.lowerImage)

	peers{prefetcher, reader}.mustReadConcurrently(t, "shared.bin", w.want["shared.bin"])

	prefetcher.Daemon.WaitFor(t, 60*time.Second, "prefetch progress", func() bool {
		v, err := prefetcher.writes(prefetchFill)
		return err == nil && v > 0
	})

	cache.waitAllReady(t, w.lowerBlob, w.sharedBlob)

	reader.mustRead(t, "shared.bin", w.want["shared.bin"])
	reader.mustRead(t, "lower.bin", w.want["lower.bin"])
}
