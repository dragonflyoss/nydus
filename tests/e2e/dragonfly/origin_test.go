package dragonfly

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func startOrigin(t testing.TB, img fixture.Image) *registry.Registry {
	t.Helper()
	r := &registry.Registry{Host: kindGateway + ":5000", URL: "http://" + kindGateway + ":5000"}
	r.PushBlobs(t, repo, img.Blobs)
	target, err := url.Parse(r.URL)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	r.Faults = &registry.Faults{}
	srv := reachableServer(t, r.Faults.Wrap(httputil.NewSingleHostReverseProxy(target)))
	r.URL, r.Host = srv.URL, strings.TrimPrefix(srv.URL, "http://")

	return r
}

func reachableServer(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", kindGateway+":0")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	srv := httptest.NewUnstartedServer(handler)
	if !assert.NoError(t, srv.Listener.Close()) {
		t.FailNow()
	}

	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)

	return srv
}

func fromSeedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	addr, parseErr := netip.ParseAddr(host)

	return err == nil && parseErr == nil && host != kindGateway &&
		netip.MustParsePrefix("172.30.0.0/16").Contains(addr) && registry.IsBlobGet(r)
}

func uniqueImage(t testing.TB) fixture.Image {
	t.Helper()
	return uniqueImageSize(t, 1<<20, "zstd-4k")
}

func uniqueImageSize(t testing.TB, size int, layoutName string) fixture.Image {
	t.Helper()
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); !assert.NoError(t, err) {
		t.FailNow()
	}
	if err := os.WriteFile(filepath.Join(src, "data"), corpus.Bytes(uint64(time.Now().UnixNano()), size), 0o644); !assert.NoError(t, err) {
		t.FailNow()
	}

	return fixture.BuildImage(t, dir, src, fixture.MustLayout(t, layoutName))
}
