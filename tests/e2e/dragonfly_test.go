package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

type dragonflyEnv struct {
	nydusBin      string
	configPath    string
	bootstrap     string
	mountpoint    string
	workDir       string
	cacheDir      string
	dragonflyMode string
}

func loadDragonflyEnv(t *testing.T) dragonflyEnv {
	t.Helper()
	workDir := envOr("WORK_DIR", "/tmp/nydus-dragonfly")
	configPath := os.Getenv("NYDUS_CONFIG")
	bootstrap := os.Getenv("BOOTSTRAP_PATH")
	require.NotEmpty(t, configPath, "NYDUS_CONFIG must be set")
	require.NotEmpty(t, bootstrap, "BOOTSTRAP_PATH must be set")

	cacheDir := os.Getenv("NYDUS_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = filepath.Join(workDir, "cache")
	}

	return dragonflyEnv{
		nydusBin:      envOr("NYDUS_BIN", mustLookupExecutable(t, "nydus")),
		configPath:    configPath,
		bootstrap:     bootstrap,
		mountpoint:    filepath.Join(workDir, "mnt"),
		workDir:       workDir,
		cacheDir:      cacheDir,
		dragonflyMode: envOr("DRAGONFLY_MODE", "sdk-proxy-fallback"),
	}
}

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
	if err == io.EOF && chosen != "" {
		path := filepath.Join(mountpoint, chosen)
		data, readErr := os.ReadFile(path)
		return chosen, data, readErr
	}

	return "", nil, os.ErrNotExist
}

func killDfdaemon(t *testing.T) {
	t.Helper()
	_ = exec.Command("pkill", "-f", "dfdaemon").Run()
	// give process supervisor-free background processes a moment to exit.
	time.Sleep(2 * time.Second)
}

func TestDragonflyE2E(t *testing.T) {
	env := loadDragonflyEnv(t)

	// In strict mode the origin configured in the nydus config is the
	// injectable proxy: it forwards to the local registry so the initial
	// read (and Dragonfly back-to-source) succeeds, and later injects hard
	// failures so origin fallback cannot succeed either.
	strict := strings.Contains(env.dragonflyMode, "strict")
	if strict {
		_, stopProxy := newInjectableProxy(t, strings.TrimPrefix(proxyControlURL, "http://"))
		defer stopProxy()
	}

	cleanup := env.startFuse(t)

	relPath, firstData, err := readMountedFile(t, env.mountpoint)
	require.NoError(t, err, "initial FUSE read must succeed")
	require.NotEmpty(t, firstData, "initial read should return data")

	killDfdaemon(t)
	wipeCacheDir(env.cacheDir)
	if strict {
		// Fail every origin blob fetch from now on: with Dragonfly down and
		// the origin hard-failing, strict mode must surface a read error.
		postInject(t, http.StatusServiceUnavailable, -1)
	}

	cleanup()
	cleanup = env.startFuse(t)
	defer cleanup()

	dataAfterFailure, err := os.ReadFile(filepath.Join(env.mountpoint, relPath))
	if strict {
		require.Error(t, err, "strict mode should fail once Dragonfly is down")
		return
	}

	require.NoError(t, err, "fallback mode should keep reads alive through origin fallback")
	require.NotEmpty(t, dataAfterFailure)
	require.NotEmpty(t, firstData)
}

type injectableProxy struct {
	targetURL *url.URL
	proxy     *httputil.ReverseProxy

	mu        sync.Mutex
	status    int
	remaining int
}

const proxyControlURL = "http://127.0.0.1:18080"

func newInjectableProxy(t *testing.T, addr string) (*injectableProxy, func()) {
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

	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	return p, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

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

func (p *injectableProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	// Only blob GETs are injected: HEAD blob-size probes stay healthy so the
	// tests exercise the data-read policy, not metadata recovery.
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

func postInject(t *testing.T, status, count int) {
	t.Helper()
	payload, err := json.Marshal(map[string]int{"status": status, "count": count})
	require.NoError(t, err)
	resp, err := http.Post(proxyControlURL+"/_test/inject", "application/json", strings.NewReader(string(payload)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func clearInject(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, proxyControlURL+"/_test/clear", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestProxyErrorSimulation(t *testing.T) {
	env := loadDragonflyEnv(t)
	configPath := os.Getenv("NYDUS_PROXY_ERROR_CONFIG")
	require.NotEmpty(t, configPath, "NYDUS_PROXY_ERROR_CONFIG must be set")
	env.configPath = configPath

	_, stopProxy := newInjectableProxy(t, strings.TrimPrefix(proxyControlURL, "http://"))
	defer stopProxy()

	// The 403 case runs first while dfdaemon's piece cache is still cold, so
	// its back-to-source fetches are guaranteed to see the injected failure.
	// It injects with no budget: every origin blob GET (Dragonfly
	// back-to-source and the direct fallback path alike) is denied, so the
	// read must surface an error no matter which path serves it.
	t.Run("status_403_terminal", func(t *testing.T) {
		postInject(t, http.StatusForbidden, -1)
		defer clearInject(t)
		wipeCacheDir(env.cacheDir)
		cleanup := env.startFuse(t)
		defer cleanup()
		_, _, err := readMountedFile(t, env.mountpoint)
		require.Error(t, err)
	})

	t.Run("status_429_ondemand_fallback", func(t *testing.T) {
		postInject(t, http.StatusTooManyRequests, 1)
		defer clearInject(t)
		wipeCacheDir(env.cacheDir)
		cleanup := env.startFuse(t)
		defer cleanup()
		_, data, err := readMountedFile(t, env.mountpoint)
		require.NoError(t, err)
		require.NotEmpty(t, data)
	})

	t.Run("status_503_retry_or_fallback", func(t *testing.T) {
		postInject(t, http.StatusServiceUnavailable, 3)
		defer clearInject(t)
		wipeCacheDir(env.cacheDir)
		cleanup := env.startFuse(t)
		defer cleanup()
		_, data, err := readMountedFile(t, env.mountpoint)
		require.NoError(t, err)
		require.NotEmpty(t, data)
	})
}
