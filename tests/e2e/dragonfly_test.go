package e2e

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

const (
	// dragonflyNamespace is the namespace the Dragonfly helm chart is
	// installed in.
	dragonflyNamespace = "dragonfly-system"

	// dragonflySeedClient is the seed client statefulset of the chart.
	dragonflySeedClient = "dragonfly-seed-client"

	// dragonflySchedulerAddr is the scheduler NodePort as the host reaches
	// it, through the kind port mapping in tests/testdata/kind.
	dragonflySchedulerAddr = "http://127.0.0.1:8002"

	// dragonflyGateway is the gateway of the kind docker network, the address
	// under which the seed peers inside the cluster reach services on the
	// host, and the source address of the host's own requests to it.
	dragonflyGateway = "172.30.0.1"

	// dragonflyRegistryAddr is the local registry as both the host and the
	// seed peers reach it.
	dragonflyRegistryAddr = dragonflyGateway + ":5000"

	// dragonflyProxyAddr is the fault proxy in front of the registry as both
	// the host and the seed peers reach it.
	dragonflyProxyAddr = dragonflyGateway + ":18080"

	// dragonflyRepository is the repository the test image is pushed to.
	dragonflyRepository = "nydus-e2e/dragonfly"

	// dragonflyArtifactDirEnv names the directory the daemon logs are kept in
	// for the workflow to upload; unset, they go under the test's temp dir.
	dragonflyArtifactDirEnv = "NYDUS_E2E_ARTIFACT_DIR"
)

// dragonflyConfig is the nydus registry backend config of one Dragonfly
// scenario.
type dragonflyConfig struct {
	// origin is the registry address the blob URLs name, the registry itself
	// or the injectable proxy in front of it.
	origin string

	// httpMaxRetries is how often the origin is retried on 429 or 5xx.
	httpMaxRetries int

	// dragonflyMaxRetries is how many seed peers a read tries before it goes
	// back to the origin.
	dragonflyMaxRetries int

	// backToSourceRateLimit is the origin request rate limit per second.
	backToSourceRateLimit int

	// prefetchScope is the prefetch scope, `none` or `all`.
	prefetchScope string
}

// write writes the config under dir and returns its path.
func (c dragonflyConfig) write(t *testing.T, dir, cacheDir string) string {
	t.Helper()
	config := fmt.Sprintf(`backend:
  type: registry
  config:
    addr: http://%s
    repository: %s
    http:
      request_timeout: 5s
      max_retries: %d
    dragonfly:
      scheduler_endpoint: %s
      request_timeout: 5s
      max_retries: %d
      back_to_source:
        request_rate_limit: %d
storage:
  dir: %s
prefetch:
  scope: %s
`, c.origin, dragonflyRepository, c.httpMaxRetries, dragonflySchedulerAddr, c.dragonflyMaxRetries, c.backToSourceRateLimit, cacheDir, c.prefetchScope)

	path := filepath.Join(dir, "nydus.yaml")
	assert.NoError(t, os.WriteFile(path, []byte(config), 0o644))
	return path
}

// dragonflyImage is the nydus image a test pushes to the local registry, with
// the source tree it was built from.
type dragonflyImage struct {
	// source is the directory the image was built from.
	source string

	// bootstrap is the bootstrap of the pushed image.
	bootstrap string
}

// dragonflyMount is a nydus mount of the test image with its metrics
// apiserver.
type dragonflyMount struct {
	// mountpoint is where the image is mounted.
	mountpoint string

	// apiserver is the Unix socket the daemon serves metrics on.
	apiserver string
}

// newDragonflyImage builds a small image with a few random files and pushes
// it to the local registry, so the seed peers can fetch its blobs from there.
func newDragonflyImage(t *testing.T) *dragonflyImage {
	t.Helper()
	assert := assert.New(t)

	// Write the source tree.
	source := filepath.Join(t.TempDir(), "source")
	assert.NoError(os.MkdirAll(filepath.Join(source, "etc"), 0o755))
	assert.NoError(os.MkdirAll(filepath.Join(source, "data"), 0o755))
	assert.NoError(os.WriteFile(filepath.Join(source, "etc", "os-release"), []byte("NAME=\"Nydus Dragonfly E2E\"\nID=nydus-e2e\n"), 0o644))
	util.WriteRandomFile(t, filepath.Join(source, "data", "blob1.bin"), 4<<20)
	util.WriteRandomFile(t, filepath.Join(source, "data", "blob2.bin"), 8<<20)

	// Convert and push the image, exporting its bootstrap through the check.
	ref := fmt.Sprintf("%s/%s:%d", dragonflyRegistryAddr, dragonflyRepository, time.Now().UnixNano())
	bootstrap := util.ConvertImage(t, nydusifyBin, nydusBin, source, ref, filepath.Join(t.TempDir(), "check"))

	return &dragonflyImage{source: source, bootstrap: bootstrap}
}

// mount mounts the image from a cold cache with the given config and returns
// the mount, unmounted when the test ends.
func (i *dragonflyImage) mount(t *testing.T, config dragonflyConfig) *dragonflyMount {
	t.Helper()
	dir := t.TempDir()
	mountpoint := filepath.Join(dir, "mnt")
	apiserver := filepath.Join(dir, "api.sock")
	logDir := filepath.Join(cmp.Or(os.Getenv(dragonflyArtifactDirEnv), dir), "logs", strings.ReplaceAll(t.Name(), "/", "_"))
	assert.NoError(t, os.MkdirAll(logDir, 0o755))

	cmd := exec.Command(
		nydusBin,
		"fuse",
		"--bootstrap", i.bootstrap,
		"--config", config.write(t, dir, filepath.Join(dir, "cache")),
		"--mountpoint", mountpoint,
		"--apiserver", "unix://"+apiserver,
		"--log-level", "info",
		"--log-dir", logDir,
	)
	t.Cleanup(util.MountFuse(t, cmd, mountpoint, "nydus fuse"))

	return &dragonflyMount{mountpoint: mountpoint, apiserver: apiserver}
}

// read reads the file at rel from the mount, checks it against the image's
// source and returns the read error, so a test can expect the failure.
func (m *dragonflyMount) read(t *testing.T, image *dragonflyImage, rel string) error {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.mountpoint, rel))
	if err != nil {
		return err
	}

	want, err := os.ReadFile(filepath.Join(image.source, rel))
	assert.NoError(t, err)
	assert.Equal(t, want, data, "%s differs from the source", rel)

	return nil
}

// backendReads returns how many reads of kind the backend served over
// protocol, from the mount's metrics.
func (m *dragonflyMount) backendReads(t *testing.T, kind, protocol string) float64 {
	t.Helper()
	return m.metric(t, "nydus_read_backend_total", kind, protocol)
}

// backendFailures returns how many reads of kind failed over protocol.
func (m *dragonflyMount) backendFailures(t *testing.T, kind, protocol string) float64 {
	t.Helper()
	return m.metric(t, "nydus_read_backend_failure_total", kind, protocol)
}

// metric returns the backend metric name summed over kind and protocol.
func (m *dragonflyMount) metric(t *testing.T, name, kind, protocol string) float64 {
	t.Helper()
	metrics := util.FetchMetrics(t, m.apiserver)
	return util.SumMetric(metrics, name, fmt.Sprintf(`type="%s"`, kind), fmt.Sprintf(`protocol="%s"`, protocol))
}

// scaleSeedClient scales the seed client statefulset to replicas and waits
// for the pods to be gone or ready.
func scaleSeedClient(t *testing.T, replicas int) {
	t.Helper()
	out, err := exec.Command("kubectl", "--namespace", dragonflyNamespace, "scale", "statefulset", dragonflySeedClient, fmt.Sprintf("--replicas=%d", replicas)).CombinedOutput()
	assert.NoError(t, err, "scale seed client: %s", out)

	if replicas == 0 {
		out, err = exec.Command("kubectl", "--namespace", dragonflyNamespace, "wait", "--for=delete", "pod", "--selector", "component=seed-client", "--timeout=3m").CombinedOutput()
	} else {
		out, err = exec.Command("kubectl", "--namespace", dragonflyNamespace, "rollout", "status", "statefulset/"+dragonflySeedClient, "--timeout=5m").CombinedOutput()
	}
	assert.NoError(t, err, "wait for seed client: %s", out)
}

// stopSeedClient takes the seed client down for the rest of the test and
// brings it back when the test ends, so the next test finds Dragonfly whole.
func stopSeedClient(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { scaleSeedClient(t, 1) })
	scaleSeedClient(t, 0)
}

// faultProxy fronts the local registry and answers the seed peers' blob GETs
// with an injected error status on demand, so a test can fail the origin
// behind Dragonfly while the daemon's own fallback reads, which come from the
// host, still reach the registry. refuse fails the host's reads too.
type faultProxy struct {
	// proxy forwards every request it does not inject into.
	proxy *httputil.ReverseProxy

	// mu guards status and remaining.
	mu sync.Mutex

	// status is the injected status, zero when disarmed.
	status int

	// remaining is the budget of blob GETs still to inject into, negative
	// for every one.
	remaining int

	// everyone injects into the host's blob GETs too, not only the seed
	// peers'.
	everyone bool

	// injected counts the blob GETs answered with the injected status.
	injected int
}

// newFaultProxy serves the proxy on every interface, so the seed peers
// reach it through the kind docker network, until the test ends.
func newFaultProxy(t *testing.T) *faultProxy {
	t.Helper()
	target, err := url.Parse("http://" + dragonflyRegistryAddr)
	assert.NoError(t, err)

	p := &faultProxy{proxy: httputil.NewSingleHostReverseProxy(target)}
	director := p.proxy.Director
	p.proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host
	}

	ln, err := net.Listen("tcp", ":18080")
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return p
}

// inject arms the proxy with status for the next count seed peer blob GETs,
// every one when count is negative.
func (p *faultProxy) inject(status, count int) {
	p.arm(status, count, false)
}

// refuse arms the proxy with status for every blob GET from anyone, the
// daemon's own reads included.
func (p *faultProxy) refuse(status int) {
	p.arm(status, -1, true)
}

// arm sets the injected status, its budget and whether the host's requests
// get it too, and restarts the injected count.
func (p *faultProxy) arm(status, count int, everyone bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = status
	p.remaining = count
	p.everyone = everyone
	p.injected = 0
}

// injectedCount returns how many blob GETs got the injected status since the
// proxy was last armed.
func (p *faultProxy) injectedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.injected
}

// ServeHTTP injects the armed status into the seed peers' blob GETs, the
// blob metadata reads of a cold cache included, until the budget runs out.
// Requests from the host and manifest requests pass through unless the
// proxy refuses everyone.
func (p *faultProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	fromSeedPeer := host != dragonflyGateway && !net.ParseIP(host).IsLoopback()

	p.mu.Lock()
	inject := (fromSeedPeer || p.everyone) && p.status > 0 && p.remaining != 0 && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/")
	if inject {
		p.injected++
		if p.remaining > 0 {
			p.remaining--
		}
	}
	status := p.status
	p.mu.Unlock()

	if !inject {
		p.proxy.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "injected"})
}

var (
	// mockDragonflyConfig reads the registry through Dragonfly and goes back
	// to the registry itself when the seed peers cannot serve.
	mockDragonflyConfig = dragonflyConfig{
		origin:                dragonflyRegistryAddr,
		httpMaxRetries:        1,
		dragonflyMaxRetries:   3,
		backToSourceRateLimit: 1000,
		prefetchScope:         "none",
	}

	// mockDragonflyProxyConfig reads through Dragonfly with the fault proxy
	// as the origin and never retries the origin, so an injected status
	// reaches the reader as is.
	mockDragonflyProxyConfig = dragonflyConfig{
		origin:                dragonflyProxyAddr,
		httpMaxRetries:        0,
		dragonflyMaxRetries:   3,
		backToSourceRateLimit: 1000,
		prefetchScope:         "none",
	}
)

func TestDragonfly_ReadThroughSeedPeer(t *testing.T) {
	assert := assert.New(t)
	image := newDragonflyImage(t)
	m := image.mount(t, mockDragonflyConfig)

	assert.NoError(m.read(t, image, "etc/os-release"))
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Positive(m.backendReads(t, "ondemand", "dragonfly"))
	assert.Zero(m.backendReads(t, "ondemand", "http"))
}

func TestDragonfly_ServedFromSeedPeerCache(t *testing.T) {
	assert := assert.New(t)
	image := newDragonflyImage(t)
	proxy := newFaultProxy(t)

	// A first mount pulls the blob into the seed peer through the origin.
	first := image.mount(t, mockDragonflyProxyConfig)
	assert.NoError(first.read(t, image, "data/blob2.bin"))

	// With the origin refusing the seed peers from now on, a second cold
	// mount is still served, from the seed peer's cache, and the origin is
	// never asked again.
	proxy.inject(http.StatusServiceUnavailable, -1)
	second := image.mount(t, mockDragonflyProxyConfig)
	assert.NoError(second.read(t, image, "data/blob2.bin"))
	assert.Positive(second.backendReads(t, "ondemand", "dragonfly"))
	assert.Zero(second.backendReads(t, "ondemand", "http"))
	assert.Zero(proxy.injectedCount())
}

func TestDragonfly_Prefetch(t *testing.T) {
	assert := assert.New(t)
	image := newDragonflyImage(t)
	config := mockDragonflyConfig
	config.prefetchScope = "all"
	m := image.mount(t, config)

	util.WaitMetricSettled(t, m.apiserver, "nydus_read_backend_total", `type="prefetch"`)
	assert.Positive(m.backendReads(t, "prefetch", "dragonfly"))
	assert.Zero(m.backendReads(t, "prefetch", "http"))
	assert.NoError(m.read(t, image, "data/blob1.bin"))
}

func TestDragonfly_ProxyError(t *testing.T) {
	proxy := newFaultProxy(t)

	tests := []struct {
		name   string
		status int
		count  int
		expect func(t *testing.T, m *dragonflyMount, proxy *faultProxy, err error)
	}{
		{
			name:   "403 on every seed peer GET fails the read without falling back",
			status: http.StatusForbidden,
			count:  -1,
			expect: func(t *testing.T, m *dragonflyMount, proxy *faultProxy, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Zero(m.backendReads(t, "ondemand", "http"))
				assert.Positive(m.backendFailures(t, "ondemand", "dragonfly"))
				assert.Positive(proxy.injectedCount())
			},
		},
		{
			name:   "429 on one seed peer GET is retried",
			status: http.StatusTooManyRequests,
			count:  1,
			expect: func(t *testing.T, m *dragonflyMount, proxy *faultProxy, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Positive(m.backendReads(t, "ondemand", "dragonfly"))
			},
		},
		{
			name:   "503 on every seed peer GET falls back to the origin",
			status: http.StatusServiceUnavailable,
			count:  -1,
			expect: func(t *testing.T, m *dragonflyMount, proxy *faultProxy, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Positive(m.backendReads(t, "ondemand", "http"))
				assert.Positive(proxy.injectedCount())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Every case gets its own image, so nothing the seed peers cached
			// for an earlier case serves this one.
			image := newDragonflyImage(t)
			proxy.inject(tc.status, tc.count)
			defer proxy.inject(0, 0)

			m := image.mount(t, mockDragonflyProxyConfig)
			tc.expect(t, m, proxy, m.read(t, image, "data/blob1.bin"))
		})
	}
}

func TestDragonfly_FallbackToOrigin(t *testing.T) {
	assert := assert.New(t)
	image := newDragonflyImage(t)
	m := image.mount(t, mockDragonflyConfig)
	assert.NoError(m.read(t, image, "data/blob1.bin"))

	// Take the seed peers away under the live mount, so the next uncached
	// read finds nobody to serve it but the origin.
	stopSeedClient(t)
	before := m.backendReads(t, "ondemand", "http")
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Greater(m.backendReads(t, "ondemand", "http"), before)
}

func TestDragonfly_OriginErrorWithoutSeedPeers(t *testing.T) {
	assert := assert.New(t)
	image := newDragonflyImage(t)
	proxy := newFaultProxy(t)
	m := image.mount(t, mockDragonflyProxyConfig)
	assert.NoError(m.read(t, image, "data/blob1.bin"))

	// With the seed peers gone, the daemon reads from the origin itself; take
	// the registry away too and the read has nowhere left to go. The proxy
	// sees the daemon's own attempt, and the failure is booked against the
	// Dragonfly client that owns the read.
	stopSeedClient(t)
	proxy.refuse(http.StatusServiceUnavailable)
	before := m.backendFailures(t, "ondemand", "dragonfly")
	assert.Error(m.read(t, image, "data/blob2.bin"))
	assert.Positive(proxy.injectedCount())
	assert.Greater(m.backendFailures(t, "ondemand", "dragonfly"), before)
}
