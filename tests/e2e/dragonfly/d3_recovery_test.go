package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// recoveryBound bounds how long a running daemon takes to use Dragonfly again
// once the cluster serves. The SDK re-lists seed peers from the scheduler
// every 60s (its default health-check interval); a refresh during the outage
// may have dropped the dead seed peer until the next one.
const recoveryBound = 90 * time.Second

// TestD3Recovery brings Dragonfly back under a running mount that fell back
// to the origin: reads go through P2P again, without a remount.
func TestD3Recovery(t *testing.T) {
	c := newCluster(t)
	// Small chunk groups fetched one at a time leave plenty of unread data,
	// so every probe below can reach the backend.
	img := fixture.Get(t, "zstd-4k-group-64k")
	origin := startOrigin(t, img)
	m := mountDragonfly(t, c, img, origin.URL, options{FetchSize: mount.Ptr[int64](0)})
	p := newProber(t, m)

	d, err := p.readBackend(t)
	if err != nil || d.of(proxyReads) == 0 {
		t.Fatalf("read before the outage: %v; want it served by Dragonfly; %v", err, d)
	}

	c.stop(t, "dfdaemon", "scheduler")
	d, err = p.readBackend(t)
	if err != nil {
		t.Fatalf("read with Dragonfly down: %v; %v", err, d)
	}
	expectFallback(t, d, "Dragonfly down")

	c.restore(t)
	start := time.Now()
	for {
		d, err := p.readBackend(t)
		if err != nil {
			t.Fatalf("read after Dragonfly came back: %v; %v", err, d)
		}
		if d.of(proxyReads) > 0 {
			t.Logf("reads go through Dragonfly again %v after it came back", time.Since(start).Round(time.Second))
			return
		}
		if time.Since(start) > recoveryBound {
			t.Fatalf("reads still bypass Dragonfly %v after it came back; %v", recoveryBound, d)
		}
		time.Sleep(time.Second)
	}
}
