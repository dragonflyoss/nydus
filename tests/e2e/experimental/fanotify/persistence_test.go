package fanotify

import (
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestPersistence fills the cache through one daemon and restarts on the
// same cache: the new daemon serves the whole tree without a single blob
// fetch and without allocating more cache.
func TestPersistence(t *testing.T) {
	t.Parallel()
	Fanotify{}.Require(t)
	s := serveDataset(t)
	cache := filepath.Join(env.WorkDir(t), "cache")

	first := s.mount(t, cache)
	mount.ReadAll(t, first.Root)
	first.Unmount()
	used, gets := cacheUsed(cache), s.blobGets()
	require.Positive(t, gets, "the first daemon fetched nothing")

	second := s.mount(t, cache)
	oracle.VerifyMount(t, second.Root, s.img.Want, s.img.Compare())
	require.Equal(t, gets, s.blobGets(), "restarted daemon fetched from the backend")
	require.Less(t, cacheUsed(cache)-used, int64(1<<20), "restarted daemon allocated cache")
}
