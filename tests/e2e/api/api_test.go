package api

import (
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestIsolation(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	a := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	b := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	if !assert.NotEqual(t, a.API.Socket, b.API.Socket) {
		t.FailNow()
	}
	if !assert.Empty(t, a.API.Trace(t).Patterns) {
		t.FailNow()
	}
	if !assert.Empty(t, b.API.Trace(t).Patterns) {
		t.FailNow()
	}

	beforeB := ondemandReads(t, b)
	fstest.VerifyMount(t, a.Root, img.Want, img.Compare())
	afterA := ondemandReads(t, a)
	if !assert.Positive(t, afterA) {
		t.FailNow()
	}

	traceA := a.API.Trace(t).Patterns
	if !assert.NotEmpty(t, traceA) {
		t.FailNow()
	}
	if !assert.Empty(t, b.API.Trace(t).Patterns) {
		t.FailNow()
	}
	if !assert.Equal(t, beforeB, ondemandReads(t, b)) {
		t.FailNow()
	}

	fstest.VerifyMount(t, b.Root, img.Want, img.Compare())

	if !assert.Greater(t, ondemandReads(t, b), beforeB) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, b.API.Trace(t).Patterns) {
		t.FailNow()
	}
	if !assert.Equal(t, traceA, a.API.Trace(t).Patterns) {
		t.FailNow()
	}

	assert.Equal(t, afterA, ondemandReads(t, a))
}

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
		r := response(t, m.API, tc.method, tc.path)
		if !assert.Equal(t, tc.status, r.status) {
			t.FailNow()
		}
		if tc.path == "/trace" && tc.status == http.StatusOK {
			assert.Equal(t, "application/json", r.header.Get("Content-Type"))
		}
	}

	for _, closeEarly := range []bool{true, false} {
		c, err := net.DialTimeout("unix", m.API.Socket, time.Second)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		t.Cleanup(func() { _ = c.Close() })

		if !assert.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second))) {
			t.FailNow()
		}

		_, err = c.Write([]byte("GET /trace HTTP/1.1\r\nHost:"))
		assert.NoError(t, err)

		if closeEarly {
			assert.NoError(t, c.Close())
			assert.Equal(t, http.StatusOK, response(t, m.API, http.MethodGet, "/metrics").status)
		}
	}

	start := time.Now()

	if !assert.True(t, m.Daemon.Stop()) {
		t.FailNow()
	}
	if !assert.Less(t, time.Since(start), 10*time.Second) {
		t.FailNow()
	}
	if !assert.Zero(t, m.Daemon.ExitCode()) {
		t.FailNow()
	}

	_, err := os.Stat(m.API.Socket)
	if !assert.ErrorIs(t, err, os.ErrNotExist) {
		t.FailNow()
	}

	m.Unmount()

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: m.API.Socket, Net: "unix"})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	stale.SetUnlinkOnClose(false)
	assert.NoError(t, stale.Close())
	_, err = os.Stat(m.API.Socket)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	req := mount.Request{Image: img, Mode: mount.Cold, Dir: env.WorkDir(t), Config: m.Config, Socket: m.API.Socket}
	_, d, stop := (mount.FUSE{}).Start(t, req)
	t.Cleanup(stop)

	api := mount.NewAPI(req.Socket)

	d.WaitFor(t, 5*time.Second, "recreated API socket", func() bool {
		_, err := api.Get("/metrics")
		return err == nil
	})

	if !assert.Equal(t, http.StatusOK, response(t, api, http.MethodGet, "/trace").status) {
		t.FailNow()
	}

	stop()
	_, err = os.Stat(req.Socket)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

type apiResponse struct {
	status int
	header http.Header
}

func response(t testing.TB, api *mount.API, method, path string) apiResponse {
	t.Helper()
	r, err := api.Do(method, path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = r.Body.Close() }()
	_, err = io.ReadAll(r.Body)
	assert.NoError(t, err)

	return apiResponse{status: r.StatusCode, header: r.Header}
}

func ondemandReads(t testing.TB, m *mount.Mounted) float64 {
	t.Helper()
	return m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`)
}
