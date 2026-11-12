package dragonfly

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestErrorCodePolicy(t *testing.T) {
	c := newCluster(t)

	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			m := c.mountFaulted(t, status)
			d, err := m.readMeasured(t, status)
			if !assert.ErrorIs(t, err, unix.EIO) {
				t.FailNow()
			}
			if !assert.NotZero(t, d.of(proxyErrors)) {
				t.FailNow()
			}

			m.Daemon.WaitForLog(t, 5*time.Second, "read failed:")

			wantFallback := status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
			got := strings.Contains(m.Daemon.FileLog(), "falling back to the origin")
			assert.Equal(t, wantFallback, got)
		})
	}

	t.Run("Unauthorized", func(t *testing.T) {
		img := uniqueImage(t)
		auth := registry.NewAuth(t, startOrigin(t, img).URL, repo)
		m := c.mount(t, img, reachableServer(t, auth).URL, policyOptions)
		d, err := m.readMeasured(t, http.StatusUnauthorized)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		issued, _ := auth.Counts()
		assert.Equal(t, 1, issued)
		assert.Zero(t, d.fallbacks)
		assert.NotZero(t, d.of(proxyReads))
	})
}

func TestSeedPeerErrors(t *testing.T) {
	c := newCluster(t)

	for _, tc := range []struct {
		status, times int
		fallback      bool
	}{
		{http.StatusForbidden, 0, false},
		{http.StatusTooManyRequests, 1, false},
		{http.StatusServiceUnavailable, 0, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			img := uniqueImage(t)
			origin := startOrigin(t, img)

			origin.Faults.Set(registry.Fault{
				Match: fromSeedPeer, Status: tc.status, Times: tc.times,
			})

			m := c.mount(t, img, origin.URL, policyOptions)
			err := m.readData(t)

			if tc.status == http.StatusForbidden {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Positive(t, origin.Faults.Hits())
			assert.Equal(t, tc.fallback, m.fallbacks() > 0)

			if tc.status == http.StatusTooManyRequests {
				assert.Positive(t, m.API.Metrics(t).Sum("nydus_backend_read_total", `source="dragonfly"`))
			}
		})
	}
}
