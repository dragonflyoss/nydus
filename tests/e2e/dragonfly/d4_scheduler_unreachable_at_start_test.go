package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// TestD4SchedulerUnreachableAtStart starts a daemon while the scheduler is
// down. Dragonfly is an accelerator, not a dependency: the mount must come up
// and serve the image from the origin.
func TestD4SchedulerUnreachableAtStart(t *testing.T) {
	c := newCluster(t)
	img := fixture.Get(t, "zstd-4k")
	origin := startOrigin(t, img)

	// Control: the same mount comes up with the scheduler running, so a
	// failure below can only be the scheduler being down.
	mountDragonfly(t, c, img, origin.URL, options{}).Unmount()
	c.stop(t, "scheduler")

	m := mountDragonfly(t, c, img, origin.URL, options{})
	d := measure(t, m, func() {
		within(t, m, imageBound, "reading the image with the scheduler down", func() {
			oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	})
	if d.of(fallbackReads) == 0 || d.of(proxyReads) != 0 {
		t.Errorf("want every backend read served by the origin; %v", d)
	}
}
