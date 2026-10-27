package dragonfly

//e2e:serial shares the Dragonfly cluster and verifies its persistent seed-peer cache.

import (
	"net/http"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestServedFromSeedPeerCache(t *testing.T) {
	c := newCluster(t)
	img := uniqueImage(t)
	origin := startOrigin(t, img)
	first := mountDragonfly(t, c, img, origin.URL, options{})
	require.NoError(t, readData(t, first))
	first.Unmount()

	origin.Faults.Set(registry.Fault{Match: fromSeedPeer, Status: http.StatusServiceUnavailable})
	second := mountDragonfly(t, c, img, origin.URL, options{})
	require.NoError(t, readData(t, second))
	require.Positive(t, second.API.Metrics(t).Sum("nydus_backend_read_total", `source="dragonfly"`))
	require.Zero(t, second.API.Metrics(t).Sum("nydus_backend_read_total", `source="fallback"`))
	require.Zero(t, origin.Faults.Hits(), "the cold mount must use the seed cache without contacting origin")
}
