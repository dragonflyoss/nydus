package e2e

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// artifactDirEnv names the directory the daemon logs are kept in for the
// workflow to upload; unset, they go under the test's temp dir.
const artifactDirEnv = "NYDUS_E2E_ARTIFACT_DIR"

// registryImage is a nydus image pushed to a registry, with the source tree
// it was built from.
type registryImage struct {
	// repository is the repository the image was pushed to.
	repository string

	// source is the directory the image was built from.
	source string

	// bootstrap is the bootstrap of the pushed image.
	bootstrap string
}

// registryMount is a `nydus fuse` mount of a registry image with its
// metrics apiserver and logs.
type registryMount struct {
	// mountpoint is where the image is mounted.
	mountpoint string

	// apiserver is the Unix socket the daemon serves metrics on.
	apiserver string

	// logDir holds the daemon's log files.
	logDir string
}

// newRegistryImage builds a small image with a few random files and pushes
// it to the registry at addr, a host:port, under repository.
func newRegistryImage(t *testing.T, addr, repository string) *registryImage {
	t.Helper()
	assert := assert.New(t)

	// Write the source tree.
	source := filepath.Join(t.TempDir(), "source")
	assert.NoError(os.MkdirAll(filepath.Join(source, "etc"), 0o755))
	assert.NoError(os.MkdirAll(filepath.Join(source, "data"), 0o755))
	assert.NoError(os.WriteFile(filepath.Join(source, "etc", "os-release"), []byte("NAME=\"Nydus E2E\"\nID=nydus-e2e\n"), 0o644))
	util.WriteRandomFile(t, filepath.Join(source, "data", "blob1.bin"), 4<<20)
	util.WriteRandomFile(t, filepath.Join(source, "data", "blob2.bin"), 8<<20)

	// Convert and push the image, exporting its bootstrap through the check.
	ref := fmt.Sprintf("%s/%s:%d", addr, repository, time.Now().UnixNano())
	bootstrap := util.ConvertImage(t, nydusifyBin, nydusBin, source, ref, filepath.Join(t.TempDir(), "check"))

	return &registryImage{repository: repository, source: source, bootstrap: bootstrap}
}

// config returns the registry backend config of the image served from the
// registry at addr, a URL with its scheme; mount places the cache.
func (i *registryImage) config(addr string) util.Config {
	return util.NewRegistryBackendConfig(addr, i.repository, "")
}

// mount mounts the image from a cold cache with config and returns the
// mount, unmounted when the test ends.
func (i *registryImage) mount(t *testing.T, config util.Config) *registryMount {
	t.Helper()
	dir := t.TempDir()
	mountpoint := filepath.Join(dir, "mnt")
	apiserver := filepath.Join(dir, "api.sock")
	logDir := filepath.Join(cmp.Or(os.Getenv(artifactDirEnv), dir), "logs", strings.ReplaceAll(t.Name(), "/", "_"))
	assert.NoError(t, os.MkdirAll(logDir, 0o755))
	assert.NoError(t, os.MkdirAll(mountpoint, 0o755))
	config.Storage.Dir = filepath.Join(dir, "cache")
	config.Write(t, filepath.Join(dir, "nydus.yaml"))

	cmd := exec.Command(
		nydusBin,
		"fuse",
		"--bootstrap", i.bootstrap,
		"--config", filepath.Join(dir, "nydus.yaml"),
		"--mountpoint", mountpoint,
		"--apiserver", "unix://"+apiserver,
		"--log-level", "info",
		"--log-dir", logDir,
	)
	t.Cleanup(util.MountFuse(t, cmd, mountpoint, "nydus fuse"))

	return &registryMount{mountpoint: mountpoint, apiserver: apiserver, logDir: logDir}
}

// read reads the file at rel from the mount, checks it against the image's
// source and returns the read error, so a test can expect the failure.
func (m *registryMount) read(t *testing.T, image *registryImage, rel string) error {
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

// backendReads returns how many reads of kind the backend made from
// source, `origin`, `proxy` or `fallback`, failed ones included, from the
// mount's metrics.
func (m *registryMount) backendReads(t *testing.T, kind, source string) float64 {
	t.Helper()
	return m.metric(t, "nydus_backend_read_total", kind, source)
}

// backendFailures returns how many reads of kind failed from source.
func (m *registryMount) backendFailures(t *testing.T, kind, source string) float64 {
	t.Helper()
	return m.metric(t, "nydus_backend_read_failure_total", kind, source)
}

// metric returns the backend metric name summed over kind and source.
func (m *registryMount) metric(t *testing.T, name, kind, source string) float64 {
	t.Helper()
	metrics := util.FetchMetrics(t, m.apiserver)
	return util.SumMetric(metrics, name, fmt.Sprintf(`type="%s"`, kind), fmt.Sprintf(`source="%s"`, source))
}

// failedReads returns how many reads the daemon logged as failed with the
// given status text, each one standing for one request before its retries.
// The daemon writes its log asynchronously, so the count is read once it
// stops growing.
func (m *registryMount) failedReads(t *testing.T, status string) int {
	t.Helper()
	count := func() int { return strings.Count(m.logs(), "read failed: unexpected status "+status) }
	last := count()
	assert.Eventually(t, func() bool {
		current := count()
		settled := current == last && current > 0
		last = current
		return settled
	}, 10*time.Second, 200*time.Millisecond, "no read failed with %s was logged", status)

	return last
}

// waitLogs waits for the daemon to log a line containing text.
func (m *registryMount) waitLogs(t *testing.T, text string) {
	t.Helper()
	assert.Eventually(t, func() bool { return strings.Contains(m.logs(), text) }, 10*time.Second, 200*time.Millisecond, "the daemon never logged %q", text)
}

// logs returns every log file of the daemon.
func (m *registryMount) logs() string {
	return util.ReadLogs(m.logDir)
}

// newRegistrySuite pushes an image to the local registry and fronts the
// registry with a proxy the test shapes, returning both and the proxy's
// host:port.
func newRegistrySuite(t *testing.T) (*registryImage, *util.RegistryProxy, string) {
	t.Helper()
	util.SkipUnlessRoot(t, "mounting FUSE")
	registry := util.SkipUnlessRegistry(t)
	image := newRegistryImage(t, registry, "nydus-e2e/registry")
	proxy := util.NewRegistryProxy(t, registry)

	return image, proxy, proxy.Serve(t, "127.0.0.1:0")
}

func TestRegistry_ReadThroughOrigin(t *testing.T) {
	assert := assert.New(t)
	image, proxy, addr := newRegistrySuite(t)
	m := image.mount(t, image.config("http://"+addr))

	assert.NoError(m.read(t, image, "etc/os-release"))
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Positive(m.backendReads(t, "ondemand", "origin"))
	assert.Zero(m.backendFailures(t, "ondemand", "origin"))
	assert.Positive(proxy.BlobGets())
}

func TestRegistry_BasicAuth(t *testing.T) {
	image, proxy, addr := newRegistrySuite(t)
	credential := base64.StdEncoding.EncodeToString([]byte("nydus:secret"))
	proxy.RequireBasic(credential)

	tests := []struct {
		name   string
		auth   string
		expect func(t *testing.T, m *registryMount, err error)
	}{
		{
			name: "the configured credential answers the challenge",
			auth: credential,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Positive(proxy.Challenges())
				assert.Zero(m.backendFailures(t, "ondemand", "origin"))
			},
		},
		{
			name: "a wrong credential fails the read",
			auth: base64.StdEncoding.EncodeToString([]byte("nydus:wrong")),
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Positive(proxy.Challenges())
				m.waitLogs(t, "401 Unauthorized")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := image.config("http://" + addr)
			config.Backend.Config.Auth = tc.auth
			m := image.mount(t, config)
			tc.expect(t, m, m.read(t, image, "data/blob1.bin"))
		})
	}
}

func TestRegistry_BearerAuth(t *testing.T) {
	assert := assert.New(t)
	image, proxy, addr := newRegistrySuite(t)
	proxy.RequireBearer("e2e-token")
	m := image.mount(t, image.config("http://"+addr))

	// The first blob GET is challenged, the token fetched from the realm
	// the challenge names, and the request sent again; the token then
	// serves every following read without another challenge.
	assert.NoError(m.read(t, image, "data/blob1.bin"))
	challenges := proxy.Challenges()
	assert.Positive(challenges)
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Equal(challenges, proxy.Challenges())
	assert.Zero(m.backendFailures(t, "ondemand", "origin"))
}

func TestRegistry_Redirect(t *testing.T) {
	assert := assert.New(t)
	image, proxy, addr := newRegistrySuite(t)
	proxy.RedirectBlobs(true)
	m := image.mount(t, image.config("http://"+addr))

	// The image holds one blob: its first GET is redirected, the location
	// cached for the blob, and every later GET of it, the second file's
	// included, goes straight to the location.
	assert.NoError(m.read(t, image, "data/blob1.bin"))
	assert.NoError(m.read(t, image, "data/blob2.bin"))
	assert.Equal(1, proxy.Redirects())
	assert.Greater(proxy.BlobGets(), 1)
	assert.Zero(m.backendFailures(t, "ondemand", "origin"))
}

func TestRegistry_Retry(t *testing.T) {
	image, proxy, addr := newRegistrySuite(t)

	tests := []struct {
		name   string
		status int
		count  int
		expect func(t *testing.T, m *registryMount, err error)
	}{
		{
			name:   "403 fails every read without a retry",
			status: http.StatusForbidden,
			count:  -1,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Equal(m.failedReads(t, "403 Forbidden"), proxy.Injected())
			},
		},
		{
			name:   "503 on two GETs is outlasted by three retries",
			status: http.StatusServiceUnavailable,
			count:  2,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(2, proxy.Injected())
				assert.Zero(m.backendFailures(t, "ondemand", "origin"))
			},
		},
		{
			name:   "503 on every GET exhausts the three retries of every read",
			status: http.StatusServiceUnavailable,
			count:  -1,
			expect: func(t *testing.T, m *registryMount, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Equal(4*m.failedReads(t, "503 Service Unavailable"), proxy.Injected())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proxy.Inject(tc.status, tc.count, nil)
			defer proxy.Inject(0, 0, nil)

			m := image.mount(t, image.config("http://"+addr))
			tc.expect(t, m, m.read(t, image, "data/blob1.bin"))
		})
	}
}

func TestRegistry_ForwardProxy(t *testing.T) {
	assert := assert.New(t)
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
	config.Backend.Config.HTTP.Proxy = &util.ProxyConfig{Addr: forward.URL}
	m := image.mount(t, config)

	assert.NoError(m.read(t, image, "data/blob1.bin"))
	assert.Positive(relayed.Load())
	assert.Positive(m.backendReads(t, "ondemand", "proxy"))
	assert.Zero(m.backendReads(t, "ondemand", "origin"))
	assert.Zero(m.backendFailures(t, "ondemand", "proxy"))
}

func TestRegistry_TLS(t *testing.T) {
	image, proxy, _ := newRegistrySuite(t)

	// Serve the proxy over TLS with a certificate a private CA signed, which
	// nothing trusts by default.
	caCert, serverCert := newTestCA(t)
	server := httptest.NewUnstartedServer(proxy)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)

	tests := []struct {
		name   string
		tls    *util.TLSConfig
		expect func(t *testing.T, err error)
	}{
		{
			name: "an untrusted certificate fails the read",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "skip_verify accepts it",
			tls:  &util.TLSConfig{SkipVerify: true},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "ca_cert trusts it",
			tls:  &util.TLSConfig{CACert: caCert},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := image.config(server.URL)
			config.Backend.Config.HTTP.TLS = tc.tls
			m := image.mount(t, config)
			tc.expect(t, m.read(t, image, "data/blob1.bin"))
		})
	}
}

func TestRegistry_PrefetchRetry(t *testing.T) {
	assert := assert.New(t)
	image, proxy, addr := newRegistrySuite(t)

	// Every blob GET fails until the prefetch has been answered once, then
	// the origin recovers; with the retry interval cut to a second, the
	// prefetch is sent once more and completes without touching the
	// on-demand path.
	proxy.Inject(http.StatusServiceUnavailable, -1, nil)
	config := image.config("http://" + addr)
	config.Backend.Config.HTTP.MaxRetries = 0
	config.Prefetch.RetryInterval = "1s"
	config.Prefetch.Scope = "all"
	m := image.mount(t, config)
	assert.Eventually(func() bool { return proxy.Injected() > 0 }, 30*time.Second, 100*time.Millisecond, "the prefetch never reached the origin")
	proxy.Inject(0, 0, nil)

	util.WaitMetricSettled(t, m.apiserver, "nydus_backend_read_total", `type="prefetch"`)
	m.waitLogs(t, "retrying in")
	assert.Positive(m.backendReads(t, "prefetch", "origin"))
	assert.NoError(m.read(t, image, "data/blob2.bin"))
}

// newTestCA creates a private CA and a server certificate it signed for
// 127.0.0.1, returning the path of the CA's PEM file and the server's key
// pair.
func newTestCA(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	assert := assert.New(t)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nydus e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	assert.NoError(err)
	caPEM := filepath.Join(t.TempDir(), "ca.pem")
	assert.NoError(os.WriteFile(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644))

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	caParsed, err := x509.ParseCertificate(caDER)
	assert.NoError(err)
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caParsed, &serverKey.PublicKey, caKey)
	assert.NoError(err)

	return caPEM, tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
}
