package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

// TestD5AllDown takes Dragonfly down and breaks the origin too: reads of data
// not yet cached fail with EIO within a bounded time, whether the origin
// refuses or hangs, and never return wrong bytes.
func TestD5AllDown(t *testing.T) {
	c := newCluster(t)
	img := fixture.Get(t, "zstd-4k")
	origin := startOrigin(t, img)
	// A short request timeout keeps the hanging-origin case well inside
	// readBound: two origin attempts of 2s each per fallback.
	m := mountDragonfly(t, c, img, origin.URL, options{Timeout: "2s"})
	p := newProber(t, m)

	d, err := p.readBackend(t)
	if err != nil || d.of(proxyReads) == 0 {
		t.Fatalf("read before the outage: %v; want it served by Dragonfly; %v", err, d)
	}

	c.stop(t, "dfdaemon", "scheduler")
	for _, step := range []struct {
		when  string
		fault registry.Fault
	}{
		{"origin answering 503", registry.Fault{Status: http.StatusServiceUnavailable}},
		{"origin hanging", registry.Fault{Delay: time.Hour}},
	} {
		origin.Faults.Set(step.fault)
		for range 2 {
			d, err := p.readBackend(t)
			expectEIO(t, err, d, "Dragonfly down, "+step.when)
			if d.of(proxyErrors) == 0 || d.of(proxyBytes) != 0 {
				t.Errorf("Dragonfly down, %s: want the read failed by its origin fallback; %v", step.when, d)
			}
			m.Daemon.WaitFor(t, 5*time.Second, "origin fallback", func() bool {
				return strings.Contains(m.Daemon.FileLog(), "falling back to the origin")
			})
		}
	}
}
