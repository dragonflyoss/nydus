package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
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

	"github.com/stretchr/testify/require"
)

// dragonflyEnv is the Dragonfly e2e environment the workflow describes through
// NYDUS_CONFIG, BOOTSTRAP_PATH, WORK_DIR, NYDUS_CACHE_DIR and DRAGONFLY_MODE.
type dragonflyEnv struct {
	nydusBin      string
	configPath    string
	bootstrap     string
	mountpoint    string
	workDir       string
	cacheDir      string
	dragonflyMode string
}

// loadDragonflyEnv reads the environment, failing the test on a missing
// config or bootstrap.
func loadDragonflyEnv(t *testing.T) dragonflyEnv {
	t.Helper()
	workDir := envOr("WORK_DIR", "/tmp/nydus-dragonfly")
	configPath := os.Getenv("NYDUS_CONFIG")
	bootstrap := os.Getenv("BOOTSTRAP_PATH")
	require.NotEmpty(t, configPath, "NYDUS_CONFIG must be set")
	require.NotEmpty(t, bootstrap, "BOOTSTRAP_PATH must be set")

	nydusBin := os.Getenv("NYDUS_BIN")
	if nydusBin == "" {
		nydusBin = mustLookupExecutable(t, "nydus")
	}

	return dragonflyEnv{
		nydusBin:      nydusBin,
		configPath:    configPath,
		bootstrap:     bootstrap,
		mountpoint:    filepath.Join(workDir, "mnt"),
		workDir:       workDir,
		cacheDir:      envOr("NYDUS_CACHE_DIR", filepath.Join(workDir, "cache")),
		dragonflyMode: envOr("DRAGONFLY_MODE", "fallback"),
	}
}

// startFuse mounts the bootstrap with the nydus config and returns the cleanup
// that unmounts it.
func (e dragonflyEnv) startFuse(t *testing.T) func() {
	t.Helper()
	require.NoError(t, os.MkdirAll(e.mountpoint, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(e.workDir, "logs"), 0o755))

	cmd := exec.Command(
		e.nydusBin,
		"fuse",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath,
		"--mountpoint", e.mountpoint,
		"--log-level", "debug",
		"--log-dir", filepath.Join(e.workDir, "logs"),
	)

	return startFuseMount(t, cmd, e.mountpoint, "nydus fuse with dragonfly")
}

// readMountedFile reads one regular file from the mounted image, preferring a
// small set of known paths and falling back to the first file found.
func readMountedFile(t *testing.T, mountpoint string) (string, []byte, error) {
	t.Helper()
	candidates := []string{"etc/os-release", "etc/passwd", "etc/group", "usr/bin/env"}
	for _, rel := range candidates {
		path := filepath.Join(mountpoint, rel)
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return rel, data, nil
		}
	}

	var chosen string
	err := filepath.WalkDir(mountpoint, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(mountpoint, path)
		if relErr != nil {
			return nil
		}
		if strings.HasPrefix(rel, "proc/") || strings.HasPrefix(rel, "sys/") {
			return nil
		}
		chosen = rel
		return io.EOF
	})
	if errors.Is(err, io.EOF) && chosen != "" {
		path := filepath.Join(mountpoint, chosen)
		data, readErr := os.ReadFile(path)
		return chosen, data, readErr
	}

	return "", nil, os.ErrNotExist
}

// stopDragonfly takes the Dragonfly deployment down through the shell command
// in DRAGONFLY_STOP_CMD (CI scales the scheduler and seed client statefulsets
// to zero and waits for the pods to terminate).
func stopDragonfly(t *testing.T) {
	t.Helper()
	command := os.Getenv("DRAGONFLY_STOP_CMD")
	require.NotEmpty(t, command, "DRAGONFLY_STOP_CMD must be set")
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	require.NoError(t, err, "stop dragonfly: %s", out)
}

// TestDragonflyE2E reads a file through Dragonfly, takes Dragonfly down and
// reads it again from a cold cache. In fallback mode the read is served by the
// origin registry. In strict mode the configured origin is the injectable
// proxy, which forwards to the registry for the first read and then injects a
// 503 on every blob GET, so the second read fails.
func TestDragonflyE2E(t *testing.T) {
	env := loadDragonflyEnv(t)
	strict := env.dragonflyMode == "strict"
	if strict {
		_, stopProxy := newInjectableProxy(t)
		defer stopProxy()
	}

	cleanup := env.startFuse(t)
	relPath, data, err := readMountedFile(t, env.mountpoint)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	stopDragonfly(t)
	wipeCacheDir(env.cacheDir)
	if strict {
		postInject(t, http.StatusServiceUnavailable, -1)
	}
	cleanup()
	cleanup = env.startFuse(t)
	defer cleanup()

	data, err = os.ReadFile(filepath.Join(env.mountpoint, relPath))
	if strict {
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

// injectableProxy fronts the local registry and injects error responses on
// blob GETs on demand, so tests can fail the origin for both Dragonfly
// back-to-source and direct fallback reads.
type injectableProxy struct {
	targetURL *url.URL
	proxy     *httputil.ReverseProxy

	mu        sync.Mutex
	status    int
	remaining int
}

// proxyListenAddr binds all interfaces: the Dragonfly seed client reaches the
// proxy from inside the kind cluster through the docker network gateway.
const proxyListenAddr = ":18080"

// proxyControlURL is where the tests reach the proxy's inject and clear
// endpoints.
const proxyControlURL = "http://127.0.0.1:18080"

// newInjectableProxy serves the proxy in front of PROXY_TARGET_URL and returns
// it with the shutdown that stops it.
func newInjectableProxy(t *testing.T) (*injectableProxy, func()) {
	t.Helper()
	targetURL, err := url.Parse(envOr("PROXY_TARGET_URL", "http://127.0.0.1:5000"))
	require.NoError(t, err)

	p := &injectableProxy{targetURL: targetURL}
	p.proxy = httputil.NewSingleHostReverseProxy(targetURL)
	p.proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	p.proxy.Director = func(req *http.Request) {
		req.URL.Scheme = p.targetURL.Scheme
		req.URL.Host = p.targetURL.Host
		req.Host = p.targetURL.Host
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_test/inject", p.inject)
	mux.HandleFunc("/_test/clear", p.clear)
	mux.HandleFunc("/", p.serve)

	ln, err := net.Listen("tcp", proxyListenAddr)
	require.NoError(t, err)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	return p, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// inject arms the proxy with a status and a budget of blob GETs to inject it
// into, a negative budget meaning every one.
func (p *injectableProxy) inject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Status int `json:"status"`
		Count  int `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.status = body.Status
	p.remaining = body.Count
	p.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// clear disarms the proxy.
func (p *injectableProxy) clear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	p.status = 0
	p.remaining = 0
	p.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// serve injects the configured status into blob GETs, the footer and blob
// metadata reads of a cold cache included, until the budget runs out; a
// negative budget never does. Manifest and token requests pass through.
func (p *injectableProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	inject := p.status > 0 && p.remaining != 0 && r.Method == http.MethodGet &&
		strings.Contains(r.URL.Path, "/blobs/")
	if inject {
		if p.remaining > 0 {
			p.remaining--
		}
		status := p.status
		p.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "injected error")
		return
	}
	p.mu.Unlock()
	p.proxy.ServeHTTP(w, r)
}

// postInject arms the proxy through its inject endpoint.
func postInject(t *testing.T, status, count int) {
	t.Helper()
	payload, err := json.Marshal(map[string]int{"status": status, "count": count})
	require.NoError(t, err)
	resp, err := http.Post(proxyControlURL+"/_test/inject", "application/json", strings.NewReader(string(payload)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// clearInject disarms the proxy through its clear endpoint.
func clearInject(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, proxyControlURL+"/_test/clear", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestProxyErrorSimulation fronts the origin with the injectable proxy and
// reads from a cold cache under each injected status. The 403 case runs first,
// while the seed peers' piece caches are still cold, so every path to the
// origin sees it.
func TestProxyErrorSimulation(t *testing.T) {
	env := loadDragonflyEnv(t)
	_, stopProxy := newInjectableProxy(t)
	defer stopProxy()

	tests := []struct {
		name   string
		status int
		count  int
		expect func(t *testing.T, data []byte, err error)
	}{
		{
			name:   "403 on every origin GET fails the read",
			status: http.StatusForbidden,
			count:  -1,
			expect: func(t *testing.T, data []byte, err error) {
				require.Error(t, err)
			},
		},
		{
			name:   "429 on one origin GET is retried on the next seed peer or the origin",
			status: http.StatusTooManyRequests,
			count:  1,
			expect: func(t *testing.T, data []byte, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, data)
			},
		},
		{
			name:   "503 on three origin GETs is outlasted by the retries and the fallback",
			status: http.StatusServiceUnavailable,
			count:  3,
			expect: func(t *testing.T, data []byte, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, data)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			postInject(t, tc.status, tc.count)
			defer clearInject(t)
			wipeCacheDir(env.cacheDir)
			cleanup := env.startFuse(t)
			defer cleanup()

			_, data, err := readMountedFile(t, env.mountpoint)
			tc.expect(t, data, err)
		})
	}
}
