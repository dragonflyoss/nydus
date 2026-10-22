package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// TestD2FallbackOnOutage takes Dragonfly down under a running mount: first
// the seed-peer dfdaemon, then the scheduler too. Reads keep returning the
// right bytes, as fallbacks to the origin, within a bounded time.
func TestD2FallbackOnOutage(t *testing.T) {
	c := newCluster(t)
	img := fixture.Get(t, "zstd-4k")
	origin := startOrigin(t, img)
	m := mountDragonfly(t, c, img, origin.URL, options{})
	p := newProber(t, m)

	d, err := p.readBackend(t)
	if err != nil || d.of(proxyReads) == 0 {
		t.Fatalf("read before the outage: %v; want it served by Dragonfly; %v", err, d)
	}

	// The seed peer dies while the scheduler still answers.
	c.stop(t, "dfdaemon")
	d, err = p.readBackend(t)
	if err != nil {
		t.Fatalf("read with dfdaemon down: %v; %v", err, d)
	}
	expectFallback(t, d, "dfdaemon down")

	// Then the whole cluster is gone: the rest of the image still reads
	// back exactly.
	c.stop(t, "scheduler")
	d = measure(t, m, func() {
		within(t, m, imageBound, "reading the image with Dragonfly down", func() {
			oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	})
	expectFallback(t, d, "dfdaemon and scheduler down")
}
