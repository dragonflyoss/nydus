package cache

import "testing"

// TestConcurrentColdReadIsConsistent is the baseline guarantee: however the
// daemons split the fills of a cold shared cache, they all read the same,
// right bytes and never a torn chunk group.
func TestConcurrentColdReadIsConsistent(t *testing.T) {
	t.Parallel()
	w := setup(t)
	mounts := mountN(t, procs, w.image1, newCache(t))

	mustReadConcurrently(t, mounts, "shared.bin", w.want["shared.bin"])
	mustReadConcurrently(t, mounts, "file1.bin", w.want["file1.bin"])
}
