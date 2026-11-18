package snapshotter

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestNydusImage(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	reg := registry.Start(t)
	img := newImage(t, reg, "snapshotter/nydus-image")
	pulled := n.pull(t, img.nydus)

	manifest, err := images.Manifest(n.ctx, n.client.ContentStore(), pulled.Target(), pulled.Platform())
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	blobs := 0
	for _, layer := range manifest.Layers {
		gets := reg.Faults.Count(func(r registry.Request) bool {
			return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/blobs/"+layer.Digest.String())
		})
		_, err := n.client.ContentStore().Info(n.ctx, layer.Digest)
		if layer.Annotations[labelNydusBlob] == "true" {
			blobs++
			assert.True(t, errdefs.IsNotFound(err))
			assert.Zero(t, gets)
			continue
		}

		assert.NoError(t, err)
		assert.Positive(t, gets)
	}

	assert.Equal(t, 3, blobs)
	c := n.start(t, pulled)
	assertFiles(t, c, img)
	unit := n.unit(t, pulled)
	n.assertRunning(t, unit)
	info := n.daemonInfo(t, pulled)
	assert.NotEmpty(t, info.Version)
	assert.Positive(t, info.PID)
	assert.Contains(t, info.Capabilities, "backend_auth_basic")
	assert.Equal(t, []string{unit}, n.units(t))
}

func TestMixedImages(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/mixed")
	oci := n.start(t, n.pull(t, img.oci))
	nydusImage := n.pull(t, img.nydus)
	nydus := n.start(t, nydusImage)

	assertFiles(t, oci, img)
	assertFiles(t, nydus, img)
	unit := n.unit(t, nydusImage)
	n.assertRunning(t, unit)
	assert.Equal(t, []string{unit}, n.units(t))
}

func TestUnlabelledPull(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/unlabelled")
	pulled, err := n.tryPull(img.nydus)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	_, err = n.tryStart(pulled)
	assert.ErrorContains(t, err, "cri.image-ref")
	tasks, err := n.client.TaskService().List(n.ctx, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Empty(t, tasks.Tasks)
	assert.Empty(t, n.units(t))
}

func TestPrefetchLabel(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/prefetch")
	pulled := n.pull(t, img.nydus, withPrefetch("all"))
	c := n.start(t, pulled)

	assertFiles(t, c, img)
	assert.Equal(t, "all", n.renderedConfig(t, pulled).Prefetch.Scope)
}

func TestPrivateRegistry(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	origin := registry.Start(t)
	auth := startBasicAuth(t, origin, "nydus", "secret")
	img := newImage(t, origin, "snapshotter/private").on(auth.host)
	n.login(t, auth.host, "nydus", "secret")
	pulled := n.pull(t, img.nydus)
	c := n.start(t, pulled)

	assertFiles(t, c, img)
	assert.Positive(t, auth.challenges.Load())
	config := n.renderedConfig(t, pulled)
	assert.Equal(t, "http://"+auth.host, config.Backend.Config.Addr)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("nydus:secret")), config.Backend.Config.Auth)
}

func TestRegistryHosts(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	origin := registry.Start(t)
	host := "registry.nydus-e2e.test"
	img := newImage(t, origin, "snapshotter/hosts").on(host)
	n.writeHosts(t, host, fmt.Sprintf("server = %q\n", origin.URL))
	pulled := n.pull(t, img.nydus, n.withHosts())
	c := n.start(t, pulled)

	assertFiles(t, c, img)
	assert.Equal(t, origin.URL, n.renderedConfig(t, pulled).Backend.Config.Addr)
	assert.Positive(t, origin.Faults.BlobGets())
}

type basicAuth struct {
	host       string
	challenges atomic.Int32
	credential atomic.Value
}

func (b *basicAuth) rotate(user, password string) {
	b.credential.Store(user + ":" + password)
}

func startBasicAuth(t *testing.T, origin *registry.Registry, user, password string) *basicAuth {
	t.Helper()
	target, err := url.Parse(origin.URL)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	b := &basicAuth{}
	b.rotate(user, password)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u+":"+p != b.credential.Load() {
			b.challenges.Add(1)
			w.Header().Set("WWW-Authenticate", `Basic realm="e2e"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	b.host = strings.TrimPrefix(srv.URL, "http://")
	return b
}

func withPrefetch(scope string) containerd.RemoteOpt {
	return containerd.WithPullSnapshotter(plugin, snapshots.WithLabels(map[string]string{labelPrefetch: scope}))
}
