package registry

import (
	"net/http"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestRetry(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)

	tests := []struct {
		name   string
		status int
		count  int
		expect func(t *testing.T, m *registryMount, err error)
	}{
		{
			name:   "ForbiddenNotRetried",
			status: http.StatusForbidden,
			count:  0,
			expect: func(t *testing.T, m *registryMount, err error) {
				if !assert.Error(t, err) {
					t.FailNow()
				}

				assert.Equal(t, m.failedReads(t, "403 Forbidden"), proxy.injected())
			},
		},
		{
			name:   "TwoUnavailableOutlasted",
			status: http.StatusServiceUnavailable,
			count:  2,
			expect: func(t *testing.T, m *registryMount, err error) {
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Equal(t, 2, proxy.injected())
				assert.Zero(t, m.backendFailures(t, "ondemand", "origin"))
			},
		},
		{
			name:   "UnavailableExhaustsRetries",
			status: http.StatusServiceUnavailable,
			count:  0,
			expect: func(t *testing.T, m *registryMount, err error) {
				if !assert.Error(t, err) {
					t.FailNow()
				}

				assert.Equal(t, 4*m.failedReads(t, "503 Service Unavailable"), proxy.injected())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxy.inject(tc.status, tc.count)
			defer proxy.inject(0, 0)
			m := image.mount(t, image.config(addr))
			tc.expect(t, m, m.read(t, image, "data/size/02097153"))
		})
	}
}

func TestPrefetchRetry(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)

	proxy.inject(http.StatusServiceUnavailable, 0)
	config := image.config(addr)
	config.HTTP.MaxRetries = mount.Ptr(0)
	config.prefetch.RetryInterval = "1s"
	config.prefetch.Scope = "all"
	m := image.mount(t, config)

	if !assert.Eventually(t, func() bool { return proxy.injected() > 0 }, 30*time.Second, 100*time.Millisecond) {
		t.FailNow()
	}

	proxy.inject(0, 0)

	m.waitMetricSettled(t, "nydus_backend_read_total", `type="prefetch"`)
	m.Daemon.WaitForLog(t, 10*time.Second, "retrying in")

	if !assert.Positive(t, m.backendReads(t, "prefetch", "origin")) {
		t.FailNow()
	}
	if !assert.Zero(t, m.backendReads(t, "ondemand", "origin")) {
		t.FailNow()
	}
	if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
		t.FailNow()
	}

	assert.Zero(t, m.backendReads(t, "ondemand", "origin"))
}

func TestPrefetchStatus(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			image, proxy, addr := newRegistrySuite(t)
			proxy.inject(status, 0)
			config := image.config(addr)
			config.HTTP.MaxRetries = mount.Ptr(0)
			config.prefetch.Scope = "all"
			config.prefetch.RetryInterval = "1s"
			m := image.mount(t, config)
			m.Daemon.WaitForLog(t, 10*time.Second, "origin request failed, retrying in")

			if !assert.Positive(t, proxy.injected()) {
				t.FailNow()
			}
			if !assert.LessOrEqual(t, proxy.injected(), 4) {
				t.FailNow()
			}

			proxy.inject(0, 0)
			m.waitMetricSettled(t, "nydus_backend_read_total", `type="prefetch"`)

			if !assert.Positive(t, m.backendReads(t, "prefetch", "origin")) {
				t.FailNow()
			}
			if !assert.Zero(t, m.backendReads(t, "ondemand", "origin")) {
				t.FailNow()
			}
			if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
				t.FailNow()
			}

			assert.Zero(t, m.backendReads(t, "ondemand", "origin"))
		})
	}
}
