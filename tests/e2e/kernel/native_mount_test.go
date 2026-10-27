package kernel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestNativeMount mounts images with the kernel EROFS driver and compares
// them with their trees: every native layout of the seeded corpus and every
// merged native image, whose blobs are the devices as they are, and the
// compressor-none layout through a device decoded from its blob meta without
// any nydus code. The kernel is also the only data oracle for the compressed
// native layouts where fsck.erofs is too old to decode them.
func TestNativeMount(t *testing.T) {
	t.Parallel()
	for _, layout := range fixture.Layouts {
		if !layout.Native {
			continue
		}
		t.Run(layout.Name, func(t *testing.T) {
			t.Parallel()
			requireKernelFor(t, layout)
			img := fixture.Get(t, layout.Name)
			mnt := mountErofs(t, img.Bootstrap, deviceFiles(t, img.Bootstrap, img.BlobDir, ""))
			oracle.VerifyMount(t, mnt, img.Want, img.Compare())
		})
	}

	for _, name := range fixture.MergeLayouts {
		layout, err := fixture.LayoutByName(name)
		require.NoError(t, err)
		if !layout.Native {
			continue
		}
		t.Run(fixture.MergedPrefix+name, func(t *testing.T) {
			t.Parallel()
			requireKernelFor(t, layout)
			img := fixture.Merged(t, layout)
			mnt := mountErofs(t, img.Bootstrap, deviceFiles(t, img.Bootstrap, img.BlobDir, ""))
			oracle.VerifyMount(t, mnt, img.Want, img.Compare())
		})
	}

	t.Run("none-4k-decoded", func(t *testing.T) {
		t.Parallel()
		layout, err := fixture.LayoutByName("none-4k")
		require.NoError(t, err)
		requireKernelFor(t, layout)
		img := fixture.Get(t, layout.Name)
		dir := env.WorkDir(t)
		device := filepath.Join(dir, filepath.Base(img.Blob()))
		require.NoError(t, os.WriteFile(device, decodeNoneBlob(t, img.Bootstrap, img.Blob()), 0o644))
		mnt := mountErofs(t, img.Bootstrap, deviceFiles(t, img.Bootstrap, dir, ""))
		oracle.VerifyMount(t, mnt, img.Want, img.Compare())
	})
}
