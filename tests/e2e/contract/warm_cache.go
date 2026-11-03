package contract

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

func runWarmCache(t *testing.T, f *Fixture) {
	backendReads := func() float64 {
		m := f.API.Metrics(t)
		// Labeled backend counters are absent until the first read.
		if !assert.True(t, m.Has("nydus_cache_bytes")) {
			t.FailNow()
		}

		return m.Sum("nydus_backend_read_total")
	}

	// Other cases read the same mount concurrently; on a warm cache none of
	// them may reach the backend either, so the delta stays exact.
	before := backendReads()
	readWant(t, f)
	assert.Equal(t, before, backendReads())
}

// readWant reads every data byte of the tree and checks it: whole files where
// the content hash is recorded, the data extents (and samples of the holes
// between them) of the large sparse ones. Unlike mount.ReadAll it does not
// stream multi-gigabyte holes through a reader that reports no holes.
func readWant(t *testing.T, f *Fixture) {
	t.Helper()
	for _, e := range f.Image.Want {
		switch {
		case e.Type != fstest.TypeReg:

		case e.SHA256 != "":
			sum, n, err := sequentialHash(f.Path(string(e.Path)), 128<<10)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, e.Size, n) {
				t.FailNow()
			}

			assert.Equal(t, e.SHA256, sum)

		default:
			fstest.VerifyExtents(t, f.Path(string(e.Path)), e.Size, e.Extents)
		}
	}
}
