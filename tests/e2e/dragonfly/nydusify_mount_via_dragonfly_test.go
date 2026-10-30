package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

// TestNydusifyMountViaDragonfly converts an image and mounts it with
// --dragonfly-scheduler: nydusify itself pulls the manifest, config and
// bootstrap through the Go SDK, and the nydus fuse it generates a config for
// reads data through the Rust SDK. Neither touches the origin directly.
func TestNydusifyMountViaDragonfly(t *testing.T) {
	c := newCluster(t)
	mount.FUSE{}.Require(t)

	// Fresh random bytes: dfdaemon keeps every blob it fetched, keyed by
	// digest, so only an unseen one proves the path through the cluster.
	src := t.TempDir()
	data := make([]byte, 1<<20)
	_, err := rand.Read(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(src, "data"), data, 0o644))

	// The origin counts the GETs of manifests and blobs coming from this
	// host, which is where nydusify and nydus fuse run. dfdaemon's own
	// back-to-source requests come from the cluster network.
	var hostGets atomic.Int64
	upstream, err := url.Parse("http://" + gateway + ":5000")
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	srv := reachableServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if r.Method == http.MethodGet && host == gateway &&
			(strings.Contains(r.URL.Path, "/blobs/sha256:") || strings.Contains(r.URL.Path, "/manifests/sha256:")) {
			hostGets.Add(1)
			t.Logf("origin GET from host: %s", r.URL.Path)
		}
		proxy.ServeHTTP(w, r)
	}))
	origin := &registry.Registry{Host: strings.TrimPrefix(srv.URL, "http://"), URL: srv.URL}

	repoName := repo + "-nydusify-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	source, target := origin.Ref(repoName, "oci"), origin.Ref(repoName, "nydus")
	origin.PushDirs(t, source, src)

	// Convert without Dragonfly: the point is to seed the registry.
	out, err := exec.Command(env.Nydusify(t), "convert", "--source", source, "--target", target,
		"--builder", env.Nydus(t), "--source-plain-http", "--target-plain-http",
		"--work-dir", t.TempDir()).CombinedOutput()
	require.NoError(t, err, string(out))

	// The apiserver socket lives in the work directory, and a socket path
	// must fit in 108 bytes.
	work, err := os.MkdirTemp("", "nydusify-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	dir := env.WorkDir(t)
	mnt := filepath.Join(dir, "mnt")
	t.Cleanup(func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	})

	hostGets.Store(0)
	d := mount.StartDaemon(t, dir, "nydusify-mount", env.Nydusify(t),
		"--dragonfly-scheduler", c.scheduler,
		"mount", "--target", target, "--mountpoint", mnt, "--work-dir", work,
		"--builder", env.Nydus(t), "--target-plain-http")
	d.WaitFor(t, time.Minute, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })
	socket := filepath.Join(work, "apiserver.sock")
	d.WaitFor(t, 10*time.Second, "apiserver at "+socket, func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	api := mount.NewAPI(socket)
	before := api.Metrics(t)
	got, err := os.ReadFile(filepath.Join(mnt, "data"))
	require.NoError(t, err, d.Log())
	require.Equal(t, data, got)
	step := delta{before: before, after: api.Metrics(t)}

	require.NotZero(t, step.of(proxyReads), "no read went through Dragonfly; %v", step)
	for _, name := range []metric{originReads, fallbackReads, proxyErrors} {
		require.Zero(t, step.of(name), "%v moved; %v", name, step)
	}
	require.Zero(t, hostGets.Load(), "nydusify pulled manifests or blobs from the origin instead of Dragonfly")
}
