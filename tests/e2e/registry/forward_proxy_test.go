package registry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestForwardProxy(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	image, _, addr := newRegistrySuite(t)

	// A forward proxy that relays the absolute-URL requests a proxied
	// client sends and counts them.
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
		for name, values := range resp.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(forward.Close)

	config := image.config("http://" + addr)
	config.HTTP.Proxy = &mount.Proxy{Addr: forward.URL}
	m := image.mount(t, config)

	require.NoError(m.read(t, image, "data/size/02097153"))
	require.Positive(relayed.Load())
	require.Positive(m.backendReads(t, "ondemand", "proxy"))
	require.Zero(m.backendReads(t, "ondemand", "origin"))
	require.Zero(m.backendFailures(t, "ondemand", "proxy"))
}
