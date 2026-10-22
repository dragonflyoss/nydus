package cache

import (
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

// TestSurvivesPeerCrash SIGKILLs a daemon while it is filling groups of the
// shared blob on demand, so it dies holding their fetch locks. A peer on the
// same cache reading the same groups must take them over and finish with the
// right bytes rather than wait on a dead owner.
func TestSurvivesPeerCrash(t *testing.T) {
	t.Parallel()
	w := setup(t)
	const repo = "e2e/cache-peer-crash"
	reg := registry.Start(t)
	reg.PushBlobs(t, repo, w.image1.Blobs)
	remote := func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(mount.Registry{Addr: reg.URL, Repository: repo})
		c.Storage.FetchSize = mount.Ptr[int64](64 << 10)
	}
	cacheDir := newCache(t)
	survivor := mountOn(t, w.image1, cacheDir, remote)
	victim := mountOn(t, w.image1, cacheDir, remote)

	// Every blob read now stalls, so the victim's fill is in flight, its
	// group locks held, when it dies.
	reg.Faults.Set(registry.Fault{Delay: 2 * time.Second})
	go func() { _, _ = readSum(victim.Path("shared.bin")) }()
	victim.Daemon.WaitFor(t, 30*time.Second, "the victim's fill to reach the registry", func() bool {
		return reg.Faults.Hits() > 0
	})
	victim.Daemon.Kill()
	reg.Faults.Clear()
	t.Logf("victim killed; shared blob all ready at the time: %v", allReady(cacheFile(cacheDir, w.keyB, mapSuffix)))

	done := make(chan readResult, 1)
	go func() {
		var r readResult
		r.sum, r.err = readSum(survivor.Path("shared.bin"))
		done <- r
	}()
	select {
	case r := <-done:
		switch {
		case r.err != nil:
			t.Errorf("survivor read: %v", r.err)
		case r.sum != w.want["shared.bin"]:
			t.Errorf("survivor read wrong bytes: sha256 %s, want %s", r.sum, w.want["shared.bin"])
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("survivor blocked after a peer crashed holding fetch locks")
	}
}
