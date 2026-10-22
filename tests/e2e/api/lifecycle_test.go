package api

import (
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestLifecycle(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/metrics", http.StatusOK},
		{http.MethodGet, "/trace", http.StatusOK},
		{http.MethodPost, "/metrics", http.StatusNotFound},
		{http.MethodDelete, "/trace", http.StatusNotFound},
		{http.MethodGet, "/missing", http.StatusNotFound},
	} {
		r := response(t, m.API.Socket, tc.method, tc.path)
		require.Equal(t, tc.status, r.StatusCode, "%s %s", tc.method, tc.path)
		if tc.path == "/trace" && tc.status == http.StatusOK {
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		}
	}
	for _, closeEarly := range []bool{true, false} {
		c, err := net.DialTimeout("unix", m.API.Socket, time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
		_, err = c.Write([]byte("GET /trace HTTP/1.1\r\nHost:"))
		require.NoError(t, err)
		if closeEarly {
			require.NoError(t, c.Close())
			require.Equal(t, http.StatusOK, response(t, m.API.Socket, http.MethodGet, "/metrics").StatusCode)
		}
	}
	start := time.Now()
	require.True(t, m.Daemon.Stop())
	require.Less(t, time.Since(start), 10*time.Second, "partial requests blocked shutdown")
	require.Zero(t, m.Daemon.ExitCode())
	_, err := os.Stat(m.API.Socket)
	require.ErrorIs(t, err, os.ErrNotExist)
	m.Unmount()

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: m.API.Socket, Net: "unix"})
	require.NoError(t, err)
	stale.SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	_, err = os.Stat(m.API.Socket)
	require.NoError(t, err, "stale socket fixture must exist")
	req := mount.Request{Image: img, Mode: mount.Cold, Dir: env.WorkDir(t), Config: m.Config, Socket: m.API.Socket}
	_, d, stop := (mount.FUSE{}).Start(t, req)
	t.Cleanup(stop)
	d.WaitFor(t, 5*time.Second, "recreated API socket", func() bool {
		_, err := mount.NewAPI(req.Socket).Get("/metrics")
		return err == nil
	})
	require.Equal(t, http.StatusOK, response(t, req.Socket, http.MethodGet, "/trace").StatusCode)
	stop()
	_, err = os.Stat(req.Socket)
	require.ErrorIs(t, err, os.ErrNotExist)
}
