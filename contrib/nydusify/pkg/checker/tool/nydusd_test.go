package tool

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMakeConfig(t *testing.T) {
	t.Run("default backend", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "nydusd.json")
		err := makeConfig(NydusdConfig{
			ConfigPath:     configPath,
			BlobCacheDir:   "/cache",
			Mode:           "direct",
			EnablePrefetch: true,
			DigestValidate: true,
			BackendType:    "",
			BackendConfig:  "",
			BootstrapPath:  "/bootstrap",
			APISockPath:    "/socket",
			MountPath:      "/mount",
			NydusdPath:     "/nydusd",
		})
		require.NoError(t, err)

		content, err := os.ReadFile(configPath)
		require.NoError(t, err)
		require.Contains(t, string(content), `"type": "localfs"`)
		require.Contains(t, string(content), `"config": {"dir": "/fake"}`)
	})

	t.Run("missing backend config", func(t *testing.T) {
		err := makeConfig(NydusdConfig{
			ConfigPath:    filepath.Join(t.TempDir(), "nydusd.json"),
			BackendType:   "registry",
			BackendConfig: "",
		})
		require.EqualError(t, err, "empty backend configuration string")
	})
}

func TestNewNydusd(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nydusd.json")
	nydusd, err := NewNydusd(NydusdConfig{
		ConfigPath:    configPath,
		BackendType:   "registry",
		BackendConfig: `{"repo":"test"}`,
	})
	require.NoError(t, err)
	require.NotNil(t, nydusd)
	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

func TestCheckReady(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nydusd.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	var requests atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/daemon" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if requests.Add(1) == 1 {
			_, _ = fmt.Fprint(w, "not-json")
			return
		}
		_, _ = fmt.Fprint(w, `{"state":"RUNNING"}`)
	})}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ready, err := checkReady(ctx, sockPath)
	require.NoError(t, err)

	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("timed out waiting for ready signal")
	}
}
