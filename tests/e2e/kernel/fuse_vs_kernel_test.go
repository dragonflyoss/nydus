package kernel

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestFUSEVsKernel mounts merged images through FUSE and the kernel EROFS
// driver side by side and requires identical trees, link counts included:
// both read the same bootstrap, so any difference is a reader bug. The
// native image gives the kernel its blobs as devices; the chunk-based one
// gives it the decoded cache data files a warm FUSE mount leaves behind,
// which therefore have to be valid EROFS devices.
func TestFUSEVsKernel(t *testing.T) {
	t.Parallel()
	for _, name := range fixture.MergeLayouts {
		layout, err := fixture.LayoutByName(name)
		require.NoError(t, err)
		if layout.Tar {
			// Reads the same as its directory-built counterpart.
			continue
		}
		t.Run(fixture.MergedPrefix+name, func(t *testing.T) {
			t.Parallel()
			requireKernelFor(t, layout)
			img := fixture.Merged(t, layout)

			var fuse *mount.Mounted
			var devices []string
			if layout.Native {
				fuse = mount.Mount(t, mount.FUSE{}, img, mount.Options{})
				devices = deviceFiles(t, img.Bootstrap, img.BlobDir, "")
			} else {
				fuse = mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mount.Warm})
				devices = deviceFiles(t, img.Bootstrap, fuse.CacheDir, ".blob.data")
			}
			kernel := mountErofs(t, img.Bootstrap, devices)

			oracle.CompareTree(t, oracle.ScanTree(t, kernel), oracle.ScanTree(t, fuse.Root), oracle.CompareOptions{Nlink: true})
			oracle.VerifyMount(t, kernel, img.Want, img.Compare())
		})
	}
}
