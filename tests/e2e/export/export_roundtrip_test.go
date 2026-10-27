package export

import (
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestExportRoundtrip rebuilds tar-layout images from their own export.
// The rebuilt image reproduces the tree up to what a tar export drops (link
// counts, hardlinks of non-regular files), and a second round trip is a
// fixed point: the same bootstrap and blob, byte for byte.
//
// Only tar layouts take part: an image built from a directory may hold
// names a layer tar cannot carry through the builder (see oracle.TarSafe).
func TestExportRoundtrip(t *testing.T) {
	t.Parallel()
	for _, layout := range fixture.Layouts {
		if !layout.Tar {
			continue
		}
		t.Run(layout.Name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, layout.Name)

			once := rebuild(t, img.Blob(), layout)
			once.Want = img.Want
			m := mount.Mount(t, mount.FUSE{}, once, mount.Options{Mode: mount.Blob})
			oracle.VerifyMount(t, m.Root, img.Want, oracle.CompareOptions{Tar: true})
			m.Unmount()

			twice := rebuild(t, once.Blob(), layout)
			require.Equal(t, fileSHA256(t, once.Bootstrap), fileSHA256(t, twice.Bootstrap), "bootstrap is not a fixed point")
			require.Equal(t, filepath.Base(once.Blob()), filepath.Base(twice.Blob()), "blob is not a fixed point")
			t.Logf("first round trip reproduces the original image byte for byte: %v",
				fileSHA256(t, img.Bootstrap) == fileSHA256(t, once.Bootstrap))
		})
	}
}
