package registry

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestBasicAuth(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	credential := base64.StdEncoding.EncodeToString([]byte("nydus:secret"))
	proxy.enableBasicAuth(credential)

	tests := []struct {
		name   string
		auth   string
		expect func(t *testing.T, m *registryMount, challenges int, err error)
	}{
		{
			name: "ConfiguredCredential",
			auth: credential,
			expect: func(t *testing.T, m *registryMount, challenges int, err error) {
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Greater(t, proxy.challengeCount(), challenges)
				assert.Zero(t, m.backendFailures(t, "ondemand", "http"))
			},
		},
		{
			name: "WrongCredentialFails",
			auth: base64.StdEncoding.EncodeToString([]byte("nydus:wrong")),
			expect: func(t *testing.T, m *registryMount, challenges int, err error) {
				if !assert.Error(t, err) {
					t.FailNow()
				}

				assert.Greater(t, proxy.challengeCount(), challenges)
				m.Daemon.WaitForLog(t, 10*time.Second, "401 Unauthorized")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			challenges := proxy.challengeCount()
			config := image.config(addr)
			config.Auth = tc.auth
			m := image.mount(t, config)
			tc.expect(t, m, challenges, m.read(t, image, "data/size/02097153"))
		})
	}
}

func TestBearerAuth(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	proxy.enableBearerAuth("e2e-token")
	m := image.mount(t, image.config(addr))
	if !assert.NoError(t, m.read(t, image, "data/size/02097153")) {
		t.FailNow()
	}

	challenges := proxy.challengeCount()
	if !assert.Positive(t, challenges) {
		t.FailNow()
	}
	if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
		t.FailNow()
	}

	assert.Equal(t, challenges, proxy.challengeCount())
	assert.Zero(t, m.backendFailures(t, "ondemand", "http"))
}

func TestBearerRefresh(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	proxy.enableBearerAuth("expiring-token")

	proxy.tokenResponse(30, 0, nil, 0)
	m := image.mount(t, image.config(addr))
	m.readWindows(t, image, 0)

	if !assert.EqualValues(t, 1, proxy.tokens.Load()) {
		t.FailNow()
	}

	challenges := proxy.challengeCount()

	proxy.tokenResponse(300, 0, nil, 200*time.Millisecond)
	time.Sleep(11 * time.Second)
	m.readWindows(t, image, 1<<20, 2<<20, 3<<20, 4<<20, 5<<20, 6<<20)

	if !assert.EqualValues(t, 2, proxy.tokens.Load()) {
		t.FailNow()
	}
	if !assert.Greater(t, proxy.challengeCount()-challenges, 1) {
		t.FailNow()
	}

	assert.LessOrEqual(t, proxy.challengeCount()-challenges, 12)
	assert.Zero(t, m.backendFailures(t, "ondemand", "http"))
}

func TestBearerPrefetchRefresh(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	proxy.enableBearerAuth("prefetch-expiring-token")
	proxy.tokenResponse(30, 0, nil, 0)

	proxy.faults.Set(registry.Fault{Times: 1, Delay: 12 * time.Second, Match: func(r *http.Request) bool {
		return registry.IsBlobGet(r) && !strings.HasPrefix(r.Header.Get("Range"), "bytes=-")
	}})

	config := image.config(addr)
	config.HTTP.RequestTimeout = "20s"
	config.prefetch.Scope = "all"
	m := image.mount(t, config)
	m.Daemon.WaitFor(t, 10*time.Second, "stalled prefetch", func() bool { return proxy.faults.Hits() > 0 })
	proxy.tokenResponse(300, 0, nil, 0)
	m.waitMetricSettled(t, "nydus_backend_read_total", `type="prefetch"`)

	if !assert.Equal(t, 1, proxy.faults.Hits()) {
		t.FailNow()
	}
	if !assert.EqualValues(t, 2, proxy.tokens.Load()) {
		t.FailNow()
	}
	if !assert.Greater(t, proxy.challengeCount(), 1) {
		t.FailNow()
	}

	assert.LessOrEqual(t, proxy.challengeCount(), 16)

	if !assert.Zero(t, m.backendFailures(t, "prefetch", "http")) {
		t.FailNow()
	}
	if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
		t.FailNow()
	}

	assert.Zero(t, m.backendReads(t, "ondemand", "http"))
}

func TestTokenServiceError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   *string
		delay  time.Duration
	}{
		{"Unavailable", http.StatusServiceUnavailable, nil, 0},
		{"Denied", http.StatusForbidden, nil, 0},
		{"MalformedJSON", http.StatusOK, mount.Ptr("{"), 0},
		{"EmptyToken", http.StatusOK, mount.Ptr(`{"token":"","expires_in":300}`), 0},
		{"Timeout", http.StatusOK, nil, 500 * time.Millisecond},
	} {
		for _, scope := range []string{"none", "all"} {
			t.Run(tc.name+"/"+scope, func(t *testing.T) {
				t.Parallel()
				image, proxy, addr := newRegistrySuite(t)
				proxy.enableBearerAuth("recovered-token")
				proxy.tokenResponse(300, tc.status, tc.body, tc.delay)
				config := image.config(addr)
				config.HTTP.MaxRetries = mount.Ptr(0)
				config.prefetch.Scope = scope

				if tc.delay > 0 {
					config.HTTP.RequestTimeout = "100ms"
				}

				m := image.mount(t, config)
				start := time.Now()

				m.expectFailure(t, scope)

				assert.Less(t, time.Since(start), 10*time.Second)

				if !assert.Positive(t, proxy.tokens.Load()) {
					t.FailNow()
				}
				if !assert.LessOrEqual(t, proxy.tokens.Load(), int32(4)) {
					t.FailNow()
				}
				if !assert.Zero(t, proxy.blobGetCount()) {
					t.FailNow()
				}
				if !assert.True(t, m.Daemon.Alive()) {
					t.FailNow()
				}

				proxy.tokenResponse(300, 0, nil, 0)
				before := proxy.tokens.Load()
				m.readWindows(t, image, 1<<20, 2<<20, 3<<20)
				assert.Equal(t, before+1, proxy.tokens.Load())
			})
		}
	}
}
