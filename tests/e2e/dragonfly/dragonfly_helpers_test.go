// Package dragonfly proves reads through Dragonfly P2P: bytes come through
// the dfdaemon proxy while the cluster is healthy, fall back to the origin
// registry while it is down, and go through Dragonfly again once it is back.
//
// The cluster uses upstream's Kind network, Helm values and NodePort service
// in tests/testdata. Manager and ordinary clients are disabled. Fault tests
// scale the scheduler or seed-client StatefulSet, restoring it on cleanup.
package dragonfly

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

const (
	schedulerEnv = "NYDUS_E2E_DRAGONFLY_SCHEDULER"
	gateway      = "172.30.0.1"

	repo = "nydus-e2e/dragonfly"

	// ondemandRetries is the Dragonfly retry budget of an on-demand read
	// before it falls back to the origin.
	ondemandRetries = 1
	// readBound bounds one read while Dragonfly or the origin is down. A
	// killed component refuses connections, so nothing should come close.
	readBound = 20 * time.Second
	// imageBound bounds reading a whole image, healthy or falling back.
	imageBound = 90 * time.Second
)

type metric struct {
	name, source string
}

// Failed reads carry the configured transport's source, even when its
// fallback failed. Successful reads identify the transport that served them.
var (
	proxyReads    = metric{"nydus_backend_read_total", "dragonfly"}
	proxyBytes    = metric{"nydus_backend_read_bytes_total", "dragonfly"}
	proxyErrors   = metric{"nydus_backend_read_failure_total", "dragonfly"}
	originReads   = metric{"nydus_backend_read_total", "origin"}
	originErrors  = metric{"nydus_backend_read_failure_total", "origin"}
	fallbackReads = metric{"nydus_backend_read_total", "fallback"}
)

// cluster is the shared Dragonfly cluster.
type cluster struct {
	scheduler string
	stopped   map[string]bool
}

// newCluster requires the cluster, brings back any component a previous test
// stopped, waits until it serves, and restarts whatever this test stops when
// it ends.
func newCluster(t *testing.T) *cluster {
	t.Helper()
	scheduler := os.Getenv(schedulerEnv)
	env.Require(t, scheduler != "", "%s is unset: start the upstream Kind/Helm cluster (see tests/e2e/README.md)", schedulerEnv)
	env.RequireRoot(t)
	_, err := exec.LookPath("kubectl")
	env.Require(t, err == nil, "kubectl is required: %v", err)
	c := &cluster{scheduler: scheduler, stopped: make(map[string]bool)}
	t.Cleanup(func() { c.restore(t) })
	return c
}

func kubectl(t env.TB, args ...string) {
	t.Helper()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--namespace", "dragonfly-system"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	t.Logf("kubectl %s: %v", strings.Join(args, " "), time.Since(start).Round(time.Millisecond))
}

// stop removes the selected pods, as in upstream's seed-peer outage tests.
func (c *cluster) stop(t env.TB, components ...string) {
	t.Helper()
	for _, component := range components {
		if component == "dfdaemon" {
			component = "seed-client"
		}
		if component != "seed-client" && component != "scheduler" {
			t.Fatalf("unknown Dragonfly component %q", component)
		}
		c.stopped[component] = true
		kubectl(t, "scale", "statefulset", "dragonfly-"+component, "--replicas=0")
		kubectl(t, "wait", "--for=delete", "pod", "--selector", "component="+component, "--timeout=3m")
	}
}

// restore starts every stopped component and waits until the cluster serves.
func (c *cluster) restore(t env.TB) {
	t.Helper()
	for _, component := range []string{"scheduler", "seed-client"} {
		if c.stopped[component] {
			kubectl(t, "scale", "statefulset", "dragonfly-"+component, "--replicas=1")
		}
	}
	for _, component := range []string{"scheduler", "seed-client"} {
		if c.stopped[component] {
			kubectl(t, "rollout", "status", "statefulset/dragonfly-"+component, "--timeout=3m")
			delete(c.stopped, component)
		}
	}
}

// startOrigin starts the origin registry holding img's blobs.
func startOrigin(t env.TB, img fixture.Image) *registry.Registry {
	t.Helper()
	r := &registry.Registry{Host: gateway + ":5000", URL: "http://" + gateway + ":5000"}
	r.PushBlobs(t, repo, img.Blobs)
	target, err := url.Parse(r.URL)
	require.NoError(t, err)
	r.Faults = &registry.Faults{}
	srv := reachableServer(t, r.Faults.Wrap(httputil.NewSingleHostReverseProxy(target)))
	r.URL, r.Host = srv.URL, strings.TrimPrefix(srv.URL, "http://")
	return r
}

func reachableServer(t env.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", gateway+":0")
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(handler)
	require.NoError(t, srv.Listener.Close())
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func fromSeedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	addr, parseErr := netip.ParseAddr(host)
	return err == nil && parseErr == nil && host != gateway &&
		netip.MustParsePrefix("172.30.0.0/16").Contains(addr) && registry.IsBlobGet(r)
}

// options tune the nydus side of a Dragonfly mount.
type options struct {
	// Timeout is the per-request timeout of origin and Dragonfly requests
	// (default 5s).
	Timeout string
	// FallbackRateLimit bounds fallback requests per second (default 20).
	FallbackRateLimit int
	// FetchSize is storage.fetch_size; nil keeps the default.
	FetchSize *int64
	// Prefetch overrides the default disabled prefetch.
	Prefetch *mount.Prefetch
}

// mountDragonfly mounts img from the origin at addr with every blob read
// routed through Dragonfly.
func mountDragonfly(t env.TB, c *cluster, img fixture.Image, addr string, o options) *mount.Mounted {
	t.Helper()
	if o.Timeout == "" {
		o.Timeout = "5s"
	}
	if o.FallbackRateLimit == 0 {
		o.FallbackRateLimit = 20
	}
	cacheDir := filepath.Join(env.WorkDir(t), "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}
	// Like a snapshotter, place each blob meta in the cache, so the backend
	// only ever reads data and every backend metric below is a data read.
	for _, blob := range img.Blobs {
		meta := filepath.Base(blob) + ".blob.meta"
		data, err := os.ReadFile(filepath.Join(filepath.Dir(blob), meta))
		if err != nil {
			t.Fatalf("read blob meta: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cacheDir, meta), data, 0o644); err != nil {
			t.Fatalf("seed blob meta: %v", err)
		}
	}
	return mount.Mount(t, mount.FUSE{}, img, mount.Options{
		CacheDir: cacheDir,
		Config: func(cfg *mount.Config) {
			cfg.Backend = mount.RegistryBackend(mount.Registry{
				Addr:       addr,
				Repository: repo,
				HTTP:       &mount.HTTP{RequestTimeout: o.Timeout, MaxRetries: mount.Ptr(1)},
				Dragonfly: &mount.Dragonfly{
					SchedulerEndpoint: c.scheduler,
					RequestTimeout:    o.Timeout,
					MaxRetries:        mount.Ptr(ondemandRetries),
					FallbackRateLimit: mount.Ptr(o.FallbackRateLimit),
				},
			})
			cfg.Storage.FetchSize = o.FetchSize
			if o.Prefetch != nil {
				cfg.Prefetch = o.Prefetch
			}
		},
	})
}

// delta is how the daemon's metrics moved across a step.
type delta struct {
	before, after mount.Metrics
}

// measure runs fn and returns how the metrics moved.
func measure(t env.TB, m *mount.Mounted, fn func()) delta {
	t.Helper()
	before := m.API.Metrics(t)
	fn()
	return delta{before: before, after: m.API.Metrics(t)}
}

func (d delta) of(m metric) float64 {
	label := `source="` + m.source + `"`
	return d.after.Sum(m.name, label) - d.before.Sum(m.name, label)
}

// backend reports whether the step reached the backend at all.
func (d delta) backend() bool {
	for _, name := range []metric{proxyReads, originReads, fallbackReads} {
		if d.of(name) != 0 {
			return true
		}
	}
	return false
}

func (d delta) String() string {
	var parts []string
	for series, v := range d.after {
		if !strings.HasPrefix(series, "nydus_backend_") || strings.Contains(series, "_duration_") {
			continue
		}
		if moved := v - d.before[series]; moved != 0 {
			parts = append(parts, fmt.Sprintf("%s +%g", series, moved))
		}
	}
	if len(parts) == 0 {
		return "no backend metric moved"
	}
	sort.Strings(parts)
	return "metrics moved: " + strings.Join(parts, ", ")
}

// expectFallback asserts that the step's backend reads all went to the origin
// as Dragonfly fallbacks, and that every fallback succeeded.
func expectFallback(t env.TB, d delta, when string) {
	t.Helper()
	if d.of(fallbackReads) == 0 {
		t.Fatalf("%s: no read fell back from Dragonfly to the origin; %v", when, d)
	}
	if d.of(proxyErrors) != 0 || d.of(proxyReads) != 0 {
		t.Errorf("%s: want every backend read served by a successful fallback; %v", when, d)
	}
}

// within runs fn, which must finish in bound. A hung read is cut off by
// tearing the mount down, which fails it, and fails the test.
func within(t env.TB, m *mount.Mounted, bound time.Duration, what string, fn func()) {
	t.Helper()
	timer := time.AfterFunc(bound, func() {
		t.Errorf("%s did not finish within %v; tearing the mount down", what, bound)
		m.Unmount()
	})
	defer timer.Stop()
	fn()
	if !timer.Stop() {
		t.FailNow()
	}
}

const (
	windowStride = 64 << 10
	windowSize   = 4 << 10
)

// window is a stretch of data (not a hole) in a file of the image.
type window struct {
	rel string
	off int64
	n   int
}

// prober reads an image's windows in turn, each one bytes the daemon has not
// served yet, so a read can reach the backend whenever the test needs one.
type prober struct {
	m       *mount.Mounted
	src     string
	windows []window
	next    int
}

// read reads the next window and returns the read error. Wrong bytes fail the
// test: a read may fail, but never return data the source does not hold.
func (p *prober) read(t env.TB) error {
	t.Helper()
	if p.next == len(p.windows) {
		t.Fatalf("read all %d windows of %s", len(p.windows), p.m.Image.Name)
	}
	w := p.windows[p.next]
	p.next++
	want := make([]byte, w.n)
	if err := readAt(filepath.Join(p.src, w.rel), w.off, want); err != nil {
		t.Fatalf("read source: %v", err)
	}
	got := make([]byte, w.n)
	if err := readAt(p.m.Path(w.rel), w.off, got); err != nil {
		return fmt.Errorf("%s at %d: %w", w.rel, w.off, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s at %d: the mount returned wrong bytes", w.rel, w.off)
	}
	return nil
}

// readBackend reads windows until one reaches the backend, each within
// readBound, and returns that read's error and how the metrics moved.
func (p *prober) readBackend(t env.TB) (delta, error) {
	t.Helper()
	for {
		var err error
		d := measure(t, p.m, func() {
			within(t, p.m, readBound, "a read", func() { err = p.read(t) })
		})
		if d.backend() {
			return d, err
		}
		if err != nil {
			t.Fatalf("read failed without reaching the backend: %v", err)
		}
	}
}

func readAt(path string, off int64, buf []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	n, err := f.ReadAt(buf, off)
	if errors.Is(err, io.EOF) && n == len(buf) {
		err = nil
	}
	return err
}

// expectEIO asserts that err is the EIO a failed backend read surfaces as.
func expectEIO(t env.TB, err error, d delta, when string) {
	t.Helper()
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("%s: read returned %v, want EIO; %v", when, err, d)
	}
}

// uniqueImage builds a one-file image of fresh random bytes. dfdaemon keeps
// every blob it fetched, keyed by digest, across tests: only a blob it has
// never seen guarantees its back-to-source request reaches the origin, where
// the test injects a status.
func uniqueImage(t env.TB) fixture.Image {
	t.Helper()
	return uniqueImageSize(t, 1<<20, "zstd-4k")
}

func uniqueImageSize(t env.TB, size int, layoutName string) fixture.Image {
	t.Helper()
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("create source: %v", err)
	}
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("random data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "data"), data, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	layout, err := fixture.LayoutByName(layoutName)
	if err != nil {
		t.Fatalf("%v", err)
	}
	blobDir := filepath.Join(dir, "blobs")
	bootstrap := filepath.Join(dir, "image.bootstrap")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, src, layout)
	return fixture.Image{
		Name:      "unique-" + layout.Name,
		Layout:    layout,
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     []string{blob},
		Source:    src,
	}
}

// readData reads the whole file of a uniqueImage mount, failing the test on
// wrong bytes, and returns the read error.
func readData(t env.TB, m *mount.Mounted) error {
	t.Helper()
	want, err := os.ReadFile(filepath.Join(m.Image.Source, "data"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	got, err := os.ReadFile(m.Path("data"))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("data: the mount returned wrong bytes")
	}
	return nil
}

// authOrigin fronts a registry with bearer-token auth, as registries with a
// token service do: a request without the token gets a 401 challenge
// pointing at /token.
type authOrigin struct {
	URL string
	// Tokens counts the tokens handed out.
	Tokens atomic.Int32
}

const authToken = "e2e-token"

func startAuthOrigin(t env.TB, r *registry.Registry) *authOrigin {
	t.Helper()
	target, err := url.Parse(r.URL)
	if err != nil {
		t.Fatalf("parse %s: %v", r.URL, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	a := &authOrigin{}
	var realm atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		a.Tokens.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":%q,"expires_in":600}`, authToken)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+authToken {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="e2e",scope="repository:%s:pull"`, realm.Load(), repo))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, req)
	})
	srv := reachableServer(t, mux)
	realm.Store(srv.URL + "/token")
	a.URL = srv.URL
	return a
}
