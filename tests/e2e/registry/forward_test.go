package registry

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestForwardProxy(t *testing.T) {
	t.Parallel()
	image, _, addr := newRegistrySuite(t)

	var relayed atomic.Int32

	forward := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayed.Add(1)
		r.RequestURI = ""

		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		defer func() { _ = resp.Body.Close() }()

		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))

	t.Cleanup(forward.Close)
	config := image.config(addr)
	config.HTTP.Proxy = &mount.ProxyConfig{Addr: forward.URL}
	m := image.mount(t, config)
	if !assert.NoError(t, m.read(t, image, "data/size/02097153")) {
		t.FailNow()
	}

	assert.Positive(t, relayed.Load())

	if !assert.Positive(t, m.backendReads(t, "ondemand", "http")) {
		t.FailNow()
	}

	assert.Zero(t, m.backendFailures(t, "ondemand", "http"))
}
