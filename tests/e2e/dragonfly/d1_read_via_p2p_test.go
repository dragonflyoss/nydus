package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// TestD1ReadViaP2P reads a whole image through a healthy cluster: every byte
// is right, and every backend read was served by the dfdaemon proxy, none by
// the origin.
func TestD1ReadViaP2P(t *testing.T) {
	c := newCluster(t)
	img := fixture.Get(t, "zstd-4k")
	origin := startOrigin(t, img)
	m := mountDragonfly(t, c, img, origin.URL, options{})

	d := measure(t, m, func() {
		within(t, m, imageBound, "reading the image", func() {
			oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	})
	if d.of(proxyReads) == 0 || d.of(proxyBytes) == 0 {
		t.Fatalf("no read went through Dragonfly; %v", d)
	}
	for _, name := range []metric{originReads, originErrors, fallbackReads, proxyErrors} {
		if d.of(name) != 0 {
			t.Errorf("%v moved: want every backend read served by Dragonfly; %v", name, d)
		}
	}

	// dfdaemon fetched what it did not hold from the origin itself.
	gets := 0
	for _, r := range origin.Faults.Requests() {
		if r.Method == http.MethodGet && strings.Contains(r.Path, "/blobs/") {
			gets++
		}
	}
	t.Logf("%v; origin saw %d blob GETs (dfdaemon back-to-source)", d, gets)
}
