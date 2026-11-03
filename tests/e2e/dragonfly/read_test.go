package dragonfly

import (
	"net/http"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestReadViaP2P(t *testing.T) {
	c := newCluster(t)
	img := fixture.Get(t, "zstd-4k")
	origin := startOrigin(t, img)
	m := c.mount(t, img, origin.URL, options{})

	d := m.measure(t, func() {
		m.within(t, imageTimeout, "reading the image", func() {
			fstest.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	})

	if !assert.NotZero(t, d.of(proxyReads)) || !assert.NotZero(t, d.of(proxyBytes)) {
		t.FailNow()
	}

	for _, name := range []metric{originReads, originErrors, fallbackReads, proxyErrors} {
		assert.Zero(t, d.of(name))
	}

	t.Logf("%v; origin saw %d blob GETs (dfdaemon back-to-source)", d, origin.Faults.BlobGets())
}

func TestServedFromSeedPeerCache(t *testing.T) {
	c := newCluster(t)
	img := uniqueImage(t)
	origin := startOrigin(t, img)
	first := c.mount(t, img, origin.URL, options{})
	if !assert.NoError(t, first.readData(t)) {
		t.FailNow()
	}

	first.Unmount()

	origin.Faults.Set(registry.Fault{Match: fromSeedPeer, Status: http.StatusServiceUnavailable})
	second := c.mount(t, img, origin.URL, options{})
	if !assert.NoError(t, second.readData(t)) {
		t.FailNow()
	}
	if !assert.Positive(t, second.API.Metrics(t).Sum("nydus_backend_read_total", `source="dragonfly"`)) {
		t.FailNow()
	}

	assert.Zero(t, second.API.Metrics(t).Sum("nydus_backend_read_total", `source="fallback"`))
	assert.Zero(t, origin.Faults.Hits())
}
