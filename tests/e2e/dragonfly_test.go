package e2e

import (
	"fmt"
	"net/http"
	"net/netip"
	"os/exec"
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
	// host.
	dragonflyGateway = "172.30.0.1"

	// dragonflyRegistryAddr is the local registry as both the host and the
	// seed peers reach it.
	dragonflyRegistryAddr = dragonflyGateway + ":5000"

	// dragonflyProxyAddr is the registry proxy as both the host and the seed
	// peers reach it.
	dragonflyProxyAddr = dragonflyGateway + ":18080"

	// dragonflyRepository is the repository the test image is pushed to.
	dragonflyRepository = "nydus-e2e/dragonfly"
)

// dragonflyNetwork is the kind docker network. The seed peers run on its
// nodes with hostNetwork, so their requests reach the host from a node
// address in it.
var dragonflyNetwork = netip.MustParsePrefix("172.30.0.0/16")

// newDragonflySuite pushes an image to the registry the seed peers reach and
// fronts that registry with a proxy on the address the seed peers reach too,
// returning both.
func newDragonflySuite(t *testing.T) (*registryImage, *util.RegistryProxy) {
	t.Helper()
	util.SkipUnlessRoot(t, "mounting FUSE")
	image := newRegistryImage(t, dragonflyRegistryAddr, dragonflyRepository)
	proxy := util.NewRegistryProxy(t, dragonflyRegistryAddr)
	proxy.Serve(t, ":18080")

	return image, proxy
}

// dragonflyConfig returns the config of the image read through Dragonfly
// with origin, the registry or the proxy, as the origin the seed peers read
// and the daemon falls back to: a read tries three seed peers before the
// daemon's own fallback, which retries the origin once and is allowed 1000
// requests per second, so neither limit shows in a test that is not about
// it.
func dragonflyConfig(image *registryImage, origin string) util.Config {
	config := image.config("http://" + origin)
	config.Backend.Config.HTTP.MaxRetries = 1
	config.Backend.Config.Dragonfly = &util.DragonflyConfig{
		SchedulerEndpoint: dragonflySchedulerAddr,
		RequestTimeout:    "5s",
		MaxRetries:        3,
		FallbackRateLimit: 1000,
	}

	return config
}

// fromSeedPeer reports whether a proxy request came from a node of the kind
// cluster rather than from the daemon on the host, whose requests come from
// the host's own addresses, the network's gateway among them.
func fromSeedPeer(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && host != dragonflyGateway && dragonflyNetwork.Contains(addr)
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

func TestDragonfly_ReadThroughSeedPeer(t *testing.T) {
	assert := assert.New(t)
	image, _ := newDragonflySuite(t)
	m := image.mount(t, dragonflyConfig(image, dragonflyRegistryAddr))

	assert.NoError(m.read(t, image, "etc/os-release"))
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Positive(m.backendReads(t, "ondemand", "proxy"))
	assert.Zero(m.backendReads(t, "ondemand", "fallback"))
}

func TestDragonfly_ServedFromSeedPeerCache(t *testing.T) {
	assert := assert.New(t)
	image, proxy := newDragonflySuite(t)
	config := dragonflyConfig(image, dragonflyProxyAddr)
	config.Backend.Config.HTTP.MaxRetries = 0

	// A first mount pulls the blob into the seed peer through the origin.
	first := image.mount(t, config)
	assert.NoError(first.read(t, image, "data/blob2.bin"))

	// With the origin refusing the seed peers from now on, a second cold
	// mount is still served, from the seed peer's cache, and the origin is
	// never asked again.
	proxy.Inject(http.StatusServiceUnavailable, -1, fromSeedPeer)
	second := image.mount(t, config)
	assert.NoError(second.read(t, image, "data/blob2.bin"))
	assert.Positive(second.backendReads(t, "ondemand", "proxy"))
	assert.Zero(second.backendReads(t, "ondemand", "fallback"))
	assert.Zero(proxy.Injected())
}

func TestDragonfly_Prefetch(t *testing.T) {
	assert := assert.New(t)
	image, _ := newDragonflySuite(t)
	config := dragonflyConfig(image, dragonflyRegistryAddr)
	config.Prefetch.Scope = "all"
	m := image.mount(t, config)

	util.WaitMetricSettled(t, m.apiserver, "nydus_backend_read_total", `type="prefetch"`)
	assert.Positive(m.backendReads(t, "prefetch", "proxy"))
	assert.Zero(m.backendReads(t, "prefetch", "fallback"))
	assert.NoError(m.read(t, image, "data/blob1.bin"))
}

func TestDragonfly_PrefetchRetry(t *testing.T) {
	assert := assert.New(t)
	image, proxy := newDragonflySuite(t)

	// The seed peers cannot reach the origin until the daemon has put a
	// failed prefetch read off to its retry; with the retry interval cut to
	// a second, that read is sent once more through the seed peers and the
	// prefetch completes without the daemon ever reading the origin itself.
	proxy.Inject(http.StatusServiceUnavailable, -1, fromSeedPeer)
	config := dragonflyConfig(image, dragonflyProxyAddr)
	config.Backend.Config.HTTP.MaxRetries = 0
	config.Backend.Config.Dragonfly.MaxRetries = 0
	config.Prefetch.RetryInterval = "1s"
	config.Prefetch.Scope = "all"
	m := image.mount(t, config)
	m.waitLogs(t, "retrying in")
	proxy.Inject(0, 0, nil)

	util.WaitMetricSettled(t, m.apiserver, "nydus_backend_read_total", `type="prefetch"`)
	assert.Positive(m.backendReads(t, "prefetch", "proxy"))
	assert.Zero(m.backendReads(t, "prefetch", "fallback"))
	assert.NoError(m.read(t, image, "data/blob2.bin"))
}

func TestDragonfly_ProxyError(t *testing.T) {
	_, proxy := newDragonflySuite(t)

	tests := []struct {
		name   string
		status int
		count  int
		expect func(t *testing.T, m *registryMount, err error)
	}{
		{
			name:   "403 on every seed peer GET fails the read without falling back",
			status: http.StatusForbidden,
			count:  -1,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Zero(m.backendReads(t, "ondemand", "fallback"))
				assert.Positive(proxy.Injected())
			},
		},
		{
			name:   "429 on one seed peer GET is retried",
			status: http.StatusTooManyRequests,
			count:  1,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Positive(m.backendReads(t, "ondemand", "proxy"))
			},
		},
		{
			name:   "503 on every seed peer GET falls back to the origin",
			status: http.StatusServiceUnavailable,
			count:  -1,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Positive(m.backendReads(t, "ondemand", "fallback"))
				assert.Positive(proxy.Injected())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Every case gets its own image, so nothing the seed peers cached
			// for an earlier case serves this one.
			image := newRegistryImage(t, dragonflyRegistryAddr, dragonflyRepository)
			proxy.Inject(tc.status, tc.count, fromSeedPeer)
			defer proxy.Inject(0, 0, nil)

			config := dragonflyConfig(image, dragonflyProxyAddr)
			config.Backend.Config.HTTP.MaxRetries = 0
			m := image.mount(t, config)
			tc.expect(t, m, m.read(t, image, "data/blob1.bin"))
		})
	}
}

func TestDragonfly_FallbackToOrigin(t *testing.T) {
	assert := assert.New(t)
	image, _ := newDragonflySuite(t)
	m := image.mount(t, dragonflyConfig(image, dragonflyRegistryAddr))
	assert.NoError(m.read(t, image, "data/blob1.bin"))

	// Take the seed peers away under the live mount, so the next uncached
	// read finds nobody to serve it but the origin.
	stopSeedClient(t)
	before := m.backendReads(t, "ondemand", "fallback")
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Greater(m.backendReads(t, "ondemand", "fallback"), before)
}

func TestDragonfly_FallbackRateLimit(t *testing.T) {
	assert := assert.New(t)
	image, proxy := newDragonflySuite(t)

	// With the seed peers gone every blob GET is the daemon's own, allowed
	// one per second: reading a blob that takes several GETs must take at
	// least a second per GET after the first.
	stopSeedClient(t)
	config := dragonflyConfig(image, dragonflyProxyAddr)
	config.Backend.Config.Dragonfly.MaxRetries = 1
	config.Backend.Config.Dragonfly.FallbackRateLimit = 1
	m := image.mount(t, config)
	start := time.Now()
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	elapsed := time.Since(start)

	gets := proxy.BlobGets()
	assert.Greater(gets, 1, "the read took a single GET, nothing to rate limit")
	assert.GreaterOrEqual(elapsed, time.Duration(gets-1)*800*time.Millisecond, "%d GETs went through faster than one per second", gets)
}

func TestDragonfly_OriginErrorWithoutSeedPeers(t *testing.T) {
	assert := assert.New(t)
	image, proxy := newDragonflySuite(t)
	config := dragonflyConfig(image, dragonflyProxyAddr)
	config.Backend.Config.HTTP.MaxRetries = 0
	m := image.mount(t, config)
	assert.NoError(m.read(t, image, "data/blob1.bin"))

	// With the seed peers gone, the daemon reads from the origin itself; take
	// the registry away too and the read has nowhere left to go.
	stopSeedClient(t)
	proxy.Inject(http.StatusServiceUnavailable, -1, nil)
	before := m.backendFailures(t, "ondemand", "proxy")
	assert.Error(m.read(t, image, "data/blob2.bin"))
	assert.Positive(proxy.Injected())
	assert.Greater(m.backendFailures(t, "ondemand", "proxy"), before)
}
