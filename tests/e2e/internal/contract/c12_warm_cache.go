package contract

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// C12: a warm mount serves the whole tree from its cache: reading every byte
// of data issues no backend read. Native erofs blobs are read in place and
// never cached (nydus-storage/src/cache/raw.rs), so the case does not apply
// to them.
func init() {
	Register(Case{
		ID: "C12", Name: "WarmCache", Scope: Data, Run: runWarmCache,
		// Needs the daemon's backend counters.
		Supports: func(a mount.Adapter, m mount.Mode, l fixture.Layout) bool {
			return m == mount.Warm && mount.TraitsOf(a).API && !l.Native
		},
	})
}

func runWarmCache(t *testing.T, f *Fixture) {
	backendReads := func() float64 {
		m := f.API.Metrics(t)
		// Labeled backend counters are absent until the first read.
		require.True(t, m.Has("nydus_cache_bytes"), "the daemon must expose cache metrics")
		return m.Sum("nydus_backend_read_total")
	}

	// Other cases read the same mount concurrently; on a warm cache none of
	// them may reach the backend either, so the delta stays exact.
	before := backendReads()
	readWant(t, f)
	require.Equal(t, before, backendReads(), "reading a warm mount fetched from the backend")
}

// readWant reads every data byte of the tree and checks it: whole files where
// the content hash is recorded, the data extents (and samples of the holes
// between them) of the large sparse ones. Unlike mount.ReadAll it does not
// stream multi-gigabyte holes through a reader that reports no holes.
func readWant(t *testing.T, f *Fixture) {
	t.Helper()
	for _, e := range f.Image.Want {
		switch {
		case e.Type != "reg":
		case e.SHA256 != "":
			sum, n, err := sequentialHash(f.At(string(e.Path)), 128<<10)
			require.NoError(t, err, "read %s", e.Path)
			require.Equal(t, e.Size, n, "%s: size", e.Path)
			require.Equal(t, e.SHA256, sum, "%s: content", e.Path)
		default:
			oracle.VerifyExtents(t, f.At(string(e.Path)), e.Size, e.Extents)
		}
	}
}
