package dragonfly

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

type mounted struct {
	*mount.Mounted
}

func (m mounted) measure(t testing.TB, fn func()) delta {
	t.Helper()
	before := m.API.Metrics(t)
	fn()

	return delta{before: before, after: m.API.Metrics(t)}
}

func (m mounted) within(t testing.TB, bound time.Duration, what string, fn func()) {
	t.Helper()
	timer := time.AfterFunc(bound, m.Unmount)

	defer timer.Stop()
	fn()

	if !timer.Stop() {
		t.Fatalf("%s did not finish within %v; tore the mount down", what, bound)
	}
}

func (m mounted) readData(t testing.TB) error {
	t.Helper()
	want, err := os.ReadFile(filepath.Join(m.Image.Source, "data"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	got, err := os.ReadFile(m.Path("data"))
	if err != nil {
		return err
	}
	if !assert.True(t, bytes.Equal(want, got)) {
		t.FailNow()
	}

	return nil
}

func (m mounted) expectNoDirectOrigin(t *testing.T) {
	t.Helper()
	metrics := m.API.Metrics(t)
	if !assert.Zero(t, metrics.Sum("nydus_backend_read_total", `source="fallback"`)) {
		t.FailNow()
	}

	assert.Zero(t, metrics.Sum("nydus_backend_read_total", `source="origin"`))
	assert.NotContains(t, m.Daemon.FileLog(), "falling back to the origin")
}

func (m mounted) waitPrefetch(t *testing.T) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		body, err := m.API.Get("/metrics")
		if err != nil {
			return false
		}

		metrics := mount.ParseMetrics(string(body))

		finished := metrics.Sum("nydus_storage_prefetch_task_total") -
			metrics.Sum("nydus_storage_prefetch_task_failure_total")

		return finished >= float64(len(m.Image.Blobs)) &&
			metrics.Sum("nydus_backend_read_total", `type="prefetch"`, `source="dragonfly"`) > 0 &&
			metrics.Sum("nydus_cache_bytes", `status="cached"`) > 0 &&
			metrics.Sum("nydus_cache_bytes", `status="uncached"`) == 0
	}, recoveryTimeout+imageTimeout, 300*time.Millisecond) {
		t.FailNow()
	}

	m.expectNoDirectOrigin(t)
}

func (m mounted) readMeasured(t testing.TB, status int) (delta, error) {
	t.Helper()
	var err error

	d := m.measure(t, func() {
		m.within(t, policyTimeout, "a read with the origin answering "+http.StatusText(status), func() { err = m.readData(t) })
	})

	return d, err
}
