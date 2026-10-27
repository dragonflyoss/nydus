package build

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestBuildExclude(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	dir := env.WorkDir(t)
	source := filepath.Join(dir, "source")
	rng := rand.New(rand.NewSource(1))
	for _, name := range []string{"keep/a.bin", "drop/b.bin", "drop/nested/c.bin", "cache.tmp"} {
		path := filepath.Join(source, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		data := make([]byte, 256<<10)
		_, err := rng.Read(data)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0o644))
	}
	layout, err := fixture.LayoutByName("zstd")
	require.NoError(t, err)
	layout.Args = append(layout.Args, "--exclude", filepath.Join(source, "drop"), "--exclude", filepath.Join(source, "cache.tmp"))
	blobDir, bootstrap := filepath.Join(dir, "blobs"), filepath.Join(dir, "image.boot")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, source, layout)
	info, err := os.Stat(blob)
	require.NoError(t, err)
	require.Less(t, info.Size(), int64(600<<10), "excluded data must not enter the blob")
	m := mount.Mount(t, mount.FUSE{}, fixture.Image{Layout: layout, Bootstrap: bootstrap, BlobDir: blobDir, Blobs: []string{blob}}, mount.Options{})
	require.NoDirExists(t, filepath.Join(m.Root, "drop"))
	require.NoFileExists(t, filepath.Join(m.Root, "cache.tmp"))
	require.Equal(t, fileSHA256(t, filepath.Join(source, "keep/a.bin")), fileSHA256(t, filepath.Join(m.Root, "keep/a.bin")))
}
