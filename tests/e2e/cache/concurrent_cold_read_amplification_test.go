package cache

import (
	"math"
	"testing"
)

// TestConcurrentColdReadAmplification measures duplicate fetching by daemons
// cold-reading one file together, against one daemon doing the same read
// alone, so the bound does not depend on the blob's group count.
func TestConcurrentColdReadAmplification(t *testing.T) {
	t.Parallel()
	w := setup(t)

	solo := mountOn(t, w.image1, newCache(t))
	mustRead(t, solo.Path("shared.bin"), w.want["shared.bin"])
	soloFill := metric(t, solo, ondemandFill)
	if soloFill <= 1 {
		t.Fatalf("solo read filled %v chunk groups; it must span several for the comparison to mean anything", soloFill)
	}

	mounts := mountN(t, procs, w.image1, newCache(t))
	mustReadConcurrently(t, mounts, "shared.bin", w.want["shared.bin"])
	total := sumMetric(t, mounts, ondemandFill)
	t.Logf("cold read amplification: solo %.0f groups, %d daemons %.0f groups (%.2fx)",
		soloFill, procs, total, total/soloFill)

	// The daemon holding a window's fetch lock publishes it and the waiters
	// find it ready, so the total should match the solo read. The slack
	// covers fetch windows of daemons at different offsets overlapping by a
	// group.
	if slack := math.Max(2, soloFill/10); total > soloFill+slack {
		t.Errorf("%d daemons filled %.0f groups, solo %.0f: concurrent cold reads refetch per daemon", procs, total, soloFill)
	}
}
