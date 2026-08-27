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
	if err == io.EOF && chosen != "" {
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

func TestDragonflyE2E(t *testing.T) {
	env := loadDragonflyEnv(t)

	// In strict mode the origin configured in the nydus config is the
	// injectable proxy: it forwards to the local registry so the initial
	// read (and Dragonfly back-to-source) succeeds, and later injects hard
	// failures so origin fallback cannot succeed either.
	strict := env.dragonflyMode == "strict"
	if strict {
		_, stopProxy := newInjectableProxy(t)
		defer stopProxy()
	}

	cleanup := env.startFuse(t)

	relPath, firstData, err := readMountedFile(t, env.mountpoint)
	require.NoError(t, err, "initial FUSE read must succeed")
	require.NotEmpty(t, firstData, "initial read should return data")

	stopDragonfly(t)
	wipeCacheDir(env.cacheDir)
	if strict {
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

const proxyControlURL = "http://127.0.0.1:18080"

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

// serve injects only blob GETs: HEAD blob-size probes stay healthy so the
// tests exercise the data-read policy, not metadata recovery.
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

	_, stopProxy := newInjectableProxy(t)
	defer stopProxy()

	// The 403 case runs first while the seed client's piece cache is still
	// cold, so its back-to-source fetches are guaranteed to see the injected
	// failure. It injects with no budget: every origin blob GET (Dragonfly
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
