package registry

import (
	"net/http"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestRedirect(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	proxy.redirectBlobs()
	m := image.mount(t, image.config(addr))
	if !assert.NoError(t, m.read(t, image, "data/size/02097153")) {
		t.FailNow()
	}
	if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
		t.FailNow()
	}
	if !assert.Equal(t, 1, proxy.redirectCount()) {
		t.FailNow()
	}

	assert.Greater(t, proxy.blobGetCount(), 1)
	assert.Zero(t, m.backendFailures(t, "ondemand", "http"))
}

func TestRedirectExpiry(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			image, proxy, addr := newRegistrySuite(t)
			proxy.redirectBlobs()
			m := image.mount(t, image.config(addr))
			m.readWindows(t, image, 0)

			if !assert.Equal(t, 1, proxy.redirectCount()) {
				t.FailNow()
			}

			proxy.expireRedirect(status)
			m.readWindows(t, image, 2<<20)

			if !assert.EqualValues(t, 1, proxy.staleRedirects.Load()) {
				t.FailNow()
			}
			if !assert.Equal(t, 2, proxy.redirectCount()) {
				t.FailNow()
			}

			m.readWindows(t, image, 4<<20)

			if !assert.Equal(t, 2, proxy.redirectCount()) {
				t.FailNow()
			}

			assert.EqualValues(t, 1, proxy.staleRedirects.Load())
			assert.Zero(t, m.backendFailures(t, "ondemand", "http"))
		})
	}
}

func TestRedirectInvalid(t *testing.T) {
	t.Parallel()
	for _, fault := range []string{"missing_location", "loop"} {
		for _, scope := range []string{"none", "all"} {
			t.Run(fault+"/"+scope, func(t *testing.T) {
				t.Parallel()
				image, proxy, addr := newRegistrySuite(t)
				proxy.redirectBlobs()
				proxy.setRedirectFault(fault)
				config := image.config(addr)
				config.HTTP.MaxRetries = mount.Ptr(0)
				config.prefetch.Scope = scope
				m := image.mount(t, config)
				start := time.Now()

				m.expectFailure(t, scope)

				assert.Less(t, time.Since(start), 10*time.Second)

				if !assert.Positive(t, proxy.redirectCount()) {
					t.FailNow()
				}
				if !assert.LessOrEqual(t, proxy.redirectCount(), 8) {
					t.FailNow()
				}
				if !assert.Zero(t, proxy.blobGetCount()) {
					t.FailNow()
				}
				if !assert.True(t, m.Daemon.Alive()) {
					t.FailNow()
				}

				proxy.setRedirectFault("")
				m.readWindows(t, image, 2<<20)
			})
		}
	}
}

func TestRedirectPrefetchExpiry(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			image, proxy, addr := newRegistrySuite(t)
			proxy.redirectBlobs()
			proxy.expireFirstCachedRedirect(status)
			config := image.config(addr)
			config.prefetch.Scope = "all"
			m := image.mount(t, config)
			m.waitMetricSettled(t, "nydus_backend_read_total", `type="prefetch"`)

			if !assert.EqualValues(t, 1, proxy.staleRedirects.Load()) {
				t.FailNow()
			}
			if !assert.Equal(t, 2, proxy.redirectCount()) {
				t.FailNow()
			}
			if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
				t.FailNow()
			}
			if !assert.Zero(t, m.backendReads(t, "ondemand", "http")) {
				t.FailNow()
			}

			assert.Zero(t, m.backendFailures(t, "prefetch", "http"))
			assert.Equal(t, 2, proxy.redirectCount())
		})
	}
}
