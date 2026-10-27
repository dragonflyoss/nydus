package cache

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestDiskless(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	dir := env.WorkDir(t)
	img := fixture.Image{Bootstrap: filepath.Join(dir, "merged.boot"), BlobDir: filepath.Join(dir, "blobs"), Merged: true}
	layout, err := fixture.LayoutByName("zstd")
	require.NoError(t, err)
	files := map[string][]byte{"first": deterministicBytes(1<<20, 1), "pressure": deterministicBytes(40<<20, 2)}
	for _, name := range []string{"first", "pressure"} {
		src := filepath.Join(dir, name)
		require.NoError(t, os.Mkdir(src, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(src, name), files[name], 0o644))
		blob, _ := fixture.BuildInto(t, img.BlobDir, filepath.Join(dir, name+".boot"), src, layout)
		img.Blobs = append(img.Blobs, blob)
	}
	fixture.Run(t, env.Nydus(t), append([]string{"merge", "--bootstrap", img.Bootstrap}, img.Blobs...)...)
	reg := registry.Start(t)
	reg.PushBlobs(t, "diskless", img.Blobs)
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Config: func(c *mount.Config) {
		c.Storage = &mount.Storage{}
		c.Backend = mount.RegistryBackend(mount.Registry{Addr: reg.URL, Repository: "diskless", HTTP: &mount.HTTP{MaxRetries: mount.Ptr(0)}})
	}})
	readFirst := func() ([]byte, error) {
		return readAt(m.Path("first"), 0, 4096)
	}
	data, err := readFirst()
	require.NoError(t, err)
	require.Equal(t, files["first"][:4096], data)
	// This other blob exceeds 32 MiB: the shared LRU must evict the first
	// blob even though its own cache has seen only one small read.
	data, err = os.ReadFile(m.Path("pressure"))
	require.NoError(t, err)
	require.Equal(t, files["pressure"], data)
	reg.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable, Match: registry.BlobGet(filepath.Base(img.Blobs[0]))})
	_, err = readFirst()
	require.Error(t, err, "evicted bytes must be fetched again, not retained in an unbounded per-blob cache")
	require.Positive(t, reg.Faults.Hits())
	reg.Faults.Clear()
	data, err = readFirst()
	require.NoError(t, err, "diskless read did not recover")
	require.Equal(t, files["first"][:4096], data)
	entries, err := os.ReadDir(m.CacheDir)
	require.NoError(t, err)
	require.Empty(t, entries, "diskless mode wrote persistent cache files")
	require.True(t, m.Daemon.Alive())
}
