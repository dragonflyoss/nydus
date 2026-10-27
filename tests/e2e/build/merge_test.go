package build

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestMerge merges the three layers of the layers corpus (every whiteout
// form, type changes, a hardlink group broken by an upper layer) built with
// each merge layout, and checks the merged bootstrap: device table, fsck,
// `nydus check`, reproducibility, and that a FUSE mount reproduces the OCI
// overlay of the layers.
func TestMerge(t *testing.T) {
	t.Parallel()
	for _, name := range fixture.MergeLayouts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layout, err := fixture.LayoutByName(name)
			require.NoError(t, err)
			dir := env.WorkDir(t)
			blobDir := filepath.Join(dir, "blobs")
			merged := filepath.Join(dir, "merged.bootstrap")

			args := []string{"merge", "--bootstrap", merged}
			var blobs []string
			for i, layer := range fixture.LayerDirs(t) {
				bootstrap := filepath.Join(dir, fmt.Sprintf("layer%d.bootstrap", i+1))
				blob, _ := fixture.BuildInto(t, blobDir, bootstrap, layer, layout)
				blobs = append(blobs, blob)
			}
			fixture.Run(t, env.Nydus(t), append(args, blobs...)...)

			tags, err := oracle.ErofsDeviceTags(merged)
			require.NoError(t, err)
			var want []string
			for _, blob := range blobs {
				want = append(want, filepath.Base(blob))
			}
			require.Equal(t, want, tags, "device table is the layers, lowest first")
			if fsckDecodes(t, layout) {
				oracle.FsckErofs(t, merged, blobDir)
			}
			requireVerified(t, merged, blobDir, blobs)

			cached := fixture.Merged(t, layout)
			require.Equal(t, fileSHA256(t, cached.Bootstrap), fileSHA256(t, merged), "merged bootstrap differs from the cached merge")

			img := cached
			img.Bootstrap, img.BlobDir, img.Blobs = merged, blobDir, blobs
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
			oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
			if !layout.Native {
				// Every layer has a visible file, all of which were just read.
				requireCacheArtifacts(t, m.CacheDir, blobs)
			}
		})
	}
}
