package conformance

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

func testWarmCache(t *testing.T, m *mounted) {
	backendReads := func() float64 {
		metrics := m.API.Metrics(t)
		if !assert.True(t, metrics.Has("nydus_cache_bytes")) {
			t.FailNow()
		}

		return metrics.Sum("nydus_backend_read_total")
	}

	before := backendReads()
	readWant(t, m)
	assert.Equal(t, before, backendReads())
}

func readWant(t *testing.T, m *mounted) {
	t.Helper()
	for _, e := range m.Image.Want {
		switch {
		case e.Type != fstest.TypeReg:

		case e.SHA256 != "":
			sum, n, err := sequentialHash(m.Path(string(e.Path)), 128<<10)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, e.Size, n) {
				t.FailNow()
			}

			assert.Equal(t, e.SHA256, sum)

		default:
			fstest.VerifyExtents(t, m.Path(string(e.Path)), e.Size, e.Extents)
		}
	}
}
