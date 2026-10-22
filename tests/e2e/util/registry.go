package util

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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// RunNydusify runs a nydusify subcommand to completion and returns
// its combined output.
func RunNydusify(t *testing.T, nydusifyBin, nydusBin string, args ...string) string {
	t.Helper()
	full := slices.Concat(args, []string{"--builder", nydusBin, "--source-plain-http", "--target-plain-http"})
	out, err := exec.Command(nydusifyBin, full...).CombinedOutput()
	assert.NoError(t, err, "nydusify %s failed: %s", strings.Join(args, " "), out)

	return string(out)
}

// MountNydusify runs `nydusify mount` on ref in the background, waits for the
// mountpoint and returns the cleanup that unmounts it. The apiserver socket
// is workDir/apiserver.sock.
func MountNydusify(t *testing.T, nydusifyBin, nydusBin, ref, mountpoint, workDir string, prefetch bool) func() {
	t.Helper()
	Unmount(mountpoint)
	assert.NoError(t, os.MkdirAll(mountpoint, 0o755))
	assert.NoError(t, os.MkdirAll(workDir, 0o755))

	args := []string{
		"mount",
		"--target", ref,
		"--mountpoint", mountpoint,
		"--work-dir", workDir,
		"--builder", nydusBin,
		"--target-plain-http",
	}
	if prefetch {
		args = append(args, "--prefetch")
	}

	return MountFuse(t, exec.Command(nydusifyBin, args...), mountpoint, "nydusify mount")
}

// ConvertImage converts the source directory to the nydus image ref,
// verifies it with `nydusify check` under workDir and returns the path of
// the bootstrap the check exported.
func ConvertImage(t *testing.T, nydusifyBin, nydusBin, source, ref, workDir string) string {
	t.Helper()
	RunNydusify(t, nydusifyBin, nydusBin, "convert", "--source", source, "--target", ref, "--target-insecure")
	RunNydusify(t, nydusifyBin, nydusBin, "check", "--target", ref, "--work-dir", workDir, "--target-insecure")

	return filepath.Join(workDir, "target", "bootstrap", "image", "image.boot")
}

// DockerBuildAndPush builds the image ref from contextDir with the given
// Dockerfile body and pushes it, removing the local copy when the test ends.
// The Dockerfile is written outside the build context so it does not end up
// in the image.
func DockerBuildAndPush(t *testing.T, contextDir, ref, dockerfile string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Dockerfile")
	assert.NoError(t, os.WriteFile(path, []byte(dockerfile), 0o644))

	out, err := exec.Command("docker", "build", "-f", path, "-t", ref, contextDir).CombinedOutput()
	if !assert.NoError(t, err, "docker build failed: %s", out) {
		return
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", ref).Run() })

	out, err = exec.Command("docker", "push", ref).CombinedOutput()
	assert.NoError(t, err, "docker push failed: %s", out)
}

// RegistryReady reports whether an OCI registry answers on host over plain
// HTTP.
func RegistryReady(host string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + host + "/v2/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	return true
}

// registryEnv names the environment variable that points the tests at a
// registry other than the local one.
const registryEnv = "NYDUS_E2E_REGISTRY"

// SkipUnlessRegistry skips the test when no registry answers at
// NYDUS_E2E_REGISTRY or localhost:5000, and returns the address of the one
// that does.
func SkipUnlessRegistry(t *testing.T) string {
	t.Helper()
	host := cmp.Or(os.Getenv(registryEnv), "localhost:5000")
	if !RegistryReady(host) {
		t.Skipf("no registry at %s (set %s or run `docker run -d -p 5000:5000 registry:2`)", host, registryEnv)
	}

	return host
}

// SkipUnlessDocker skips the test when the docker CLI or daemon is unavailable.
func SkipUnlessDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}

// RegistryProxy fronts a registry and shapes what a client sees: an error
// status injected into blob GETs, a Basic or Bearer challenge every request
// must answer, blob GETs redirected to a second URL, and counters of what it
// did, so a test can prove the client took the path it expects. Everything
// else passes through to the registry.
type RegistryProxy struct {
	// target is the registry the proxy forwards to.
	target *url.URL

	// proxy forwards every request the proxy does not answer itself.
	proxy *httputil.ReverseProxy

	// mu guards every field below.
	mu sync.Mutex

	// status is the injected status, zero when disarmed.
	status int

	// remaining is the budget of blob GETs still to inject into, negative
	// for every one.
	remaining int

	// from selects the clients that get the injected status by remote host,
	// nil for every client.
	from func(host string) bool

	// basic is the Basic credential every request must carry, empty when
	// no challenge is issued.
	basic string

	// bearer is the Bearer token every request must carry, empty when no
	// challenge is issued; the proxy's own /token endpoint hands it out.
	bearer string

	// redirect answers blob GETs with a 307 to the proxy's /redirected path.
	redirect bool

	// injected counts the blob GETs answered with the injected status.
	injected int

	// challenges counts the 401 answers.
	challenges int

	// redirects counts the 307 answers.
	redirects int

	// blobGets counts the blob GETs that reached the registry.
	blobGets int
}

// NewRegistryProxy returns a proxy in front of the registry at target, a
// host:port, ready to be served by Serve or by an httptest server.
func NewRegistryProxy(t *testing.T, target string) *RegistryProxy {
	t.Helper()
	u, err := url.Parse("http://" + target)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	p := &RegistryProxy{target: u, proxy: httputil.NewSingleHostReverseProxy(u)}
	director := p.proxy.Director
	p.proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = u.Host
	}

	return p
}

// Serve listens on addr, "127.0.0.1:0" for any free port, until the test
// ends and returns the host:port it listens on.
func (p *RegistryProxy) Serve(t *testing.T, addr string) string {
	t.Helper()
	listener, err := net.Listen("tcp", addr)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	server := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return listener.Addr().String()
}

// Inject arms the proxy with status for the next count blob GETs from the
// clients from selects, every one when count is negative, every client when
// from is nil, and restarts the injected count.
func (p *RegistryProxy) Inject(status, count int, from func(host string) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = status
	p.remaining = count
	p.from = from
	p.injected = 0
}

// RequireBasic makes the proxy challenge every request that does not carry
// the Basic credential, the base64 of user:password, with a 401.
func (p *RegistryProxy) RequireBasic(credential string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.basic = credential
}

// RequireBearer makes the proxy challenge every request that does not carry
// the Bearer token with a 401 naming its own /token endpoint, which answers
// with that token.
func (p *RegistryProxy) RequireBearer(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bearer = token
}

// RedirectBlobs makes the proxy answer blob GETs with a 307 to its own
// /redirected path, which serves them.
func (p *RegistryProxy) RedirectBlobs(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirect = on
}

// Injected returns how many blob GETs got the injected status since Inject.
func (p *RegistryProxy) Injected() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.injected
}

// Challenges returns how many requests were answered with a 401.
func (p *RegistryProxy) Challenges() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.challenges
}

// Redirects returns how many blob GETs were answered with a 307.
func (p *RegistryProxy) Redirects() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.redirects
}

// BlobGets returns how many blob GETs reached the registry.
func (p *RegistryProxy) BlobGets() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.blobGets
}

// ServeHTTP answers the token endpoint, challenges, injects and redirects as
// armed, in that order, and forwards everything else to the registry. A
// redirected blob GET comes back on the /redirected path and is forwarded
// with the path restored.
func (p *RegistryProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		p.mu.Lock()
		token := p.bearer
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_in": 300})
		return
	}

	redirected := strings.HasPrefix(r.URL.Path, "/redirected/")
	if redirected {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/redirected")
	}
	blobGet := r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/")
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	p.mu.Lock()
	switch {
	case p.basic != "" && r.Header.Get("Authorization") != "Basic "+p.basic:
		p.challenges++
		p.mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="e2e"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	case p.bearer != "" && r.Header.Get("Authorization") != "Bearer "+p.bearer:
		p.challenges++
		p.mu.Unlock()
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s://%s/token",service="e2e",scope="repository:e2e:pull"`, scheme, r.Host))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case blobGet && p.status > 0 && p.remaining != 0 && (p.from == nil || p.from(host)):
		p.injected++
		if p.remaining > 0 {
			p.remaining--
		}
		status := p.status
		p.mu.Unlock()
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "injected"})
		return
	case blobGet && p.redirect && !redirected:
		p.redirects++
		p.mu.Unlock()
		w.Header().Set("Location", scheme+"://"+r.Host+"/redirected"+r.URL.RequestURI())
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	if blobGet {
		p.blobGets++
	}
	p.mu.Unlock()

	p.proxy.ServeHTTP(w, r)
}
