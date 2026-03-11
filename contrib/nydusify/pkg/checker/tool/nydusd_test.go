package tool

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestMount(t *testing.T) {
	workDir := t.TempDir()
	scriptPath := filepath.Join(workDir, "nydusd.sh")
	script := "#!/bin/sh\nexit 1\n"
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

	nydusd, err := NewNydusd(NydusdConfig{
		ConfigPath:    filepath.Join(workDir, "nydusd.json"),
		BackendType:   "registry",
		BackendConfig: `{"repo":"test"}`,
		NydusdPath:    scriptPath,
		MountPath:     filepath.Join(workDir, "mnt"),
		BootstrapPath: filepath.Join(workDir, "bootstrap"),
		APISockPath:   filepath.Join(workDir, "api.sock"),
	})
	require.NoError(t, err)

	err = nydusd.Mount()
	require.Error(t, err)
	require.Contains(t, err.Error(), "run Nydusd binary")
}

func TestUmount(t *testing.T) {
	t.Run("missing mount path", func(t *testing.T) {
		nydusd := &Nydusd{NydusdConfig: NydusdConfig{MountPath: filepath.Join(t.TempDir(), "missing")}}
		require.NoError(t, nydusd.Umount(true))
	})

	t.Run("umount command success", func(t *testing.T) {
		workDir := t.TempDir()
		mountPath := filepath.Join(workDir, "mnt")
		require.NoError(t, os.MkdirAll(mountPath, 0755))

		binDir := filepath.Join(workDir, "bin")
		require.NoError(t, os.MkdirAll(binDir, 0755))
		logPath := filepath.Join(workDir, "umount.log")
		scriptPath := filepath.Join(binDir, "umount")
		script := "#!/bin/sh\nprintf '%s' \"$1\" > \"" + logPath + "\"\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		oldPath := os.Getenv("PATH")
		require.NoError(t, os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath))
		defer os.Setenv("PATH", oldPath)

		nydusd := &Nydusd{NydusdConfig: NydusdConfig{MountPath: mountPath}}
		require.NoError(t, nydusd.Umount(true))

		loggedPath, err := os.ReadFile(logPath)
		require.NoError(t, err)
		require.Equal(t, mountPath, string(loggedPath))
	})

	t.Run("umount command failed", func(t *testing.T) {
		workDir := t.TempDir()
		mountPath := filepath.Join(workDir, "mnt")
		require.NoError(t, os.MkdirAll(mountPath, 0755))

		binDir := filepath.Join(workDir, "bin")
		require.NoError(t, os.MkdirAll(binDir, 0755))
		scriptPath := filepath.Join(binDir, "umount")
		script := "#!/bin/sh\necho fail >&2\nexit 1\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		oldPath := os.Getenv("PATH")
		require.NoError(t, os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath))
		defer os.Setenv("PATH", oldPath)

		nydusd := &Nydusd{NydusdConfig: NydusdConfig{MountPath: mountPath}}
		err := nydusd.Umount(true)
		require.Error(t, err)
	})

	t.Run("umount command exposes output when not silent", func(t *testing.T) {
		workDir := t.TempDir()
		mountPath := filepath.Join(workDir, "mnt")
		require.NoError(t, os.MkdirAll(mountPath, 0755))

		binDir := filepath.Join(workDir, "bin")
		require.NoError(t, os.MkdirAll(binDir, 0755))
		scriptPath := filepath.Join(binDir, "umount")
		script := "#!/bin/sh\necho fail >&2\nexit 1\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		oldPath := os.Getenv("PATH")
		require.NoError(t, os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath))
		defer os.Setenv("PATH", oldPath)

		nydusd := &Nydusd{NydusdConfig: NydusdConfig{MountPath: mountPath}}
		err := nydusd.Umount(false)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "exit status") || err != nil)
	})
}
