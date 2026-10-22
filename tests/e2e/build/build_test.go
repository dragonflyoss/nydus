package build

import (
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestBuild builds the seeded corpus with every GA layout and checks what the
// builder wrote: the blob store contract, the footer, the device table,
// fsck.erofs, `nydus check` in both modes, and that a second process builds
// the very same bytes. Reading the images back is the contract suite's job.
func TestBuild(t *testing.T) {
	t.Parallel()
	for _, layout := range fixture.Layouts {
		t.Run(layout.Name, func(t *testing.T) {
			t.Parallel()
			dir := env.WorkDir(t)
			blobDir := filepath.Join(dir, "blobs")
			bootstrap := filepath.Join(dir, "image.bootstrap")
			// BuildInto asserts one SHA256-named blob, with a blob meta
			// unless the layout is native.
			blob, _ := fixture.BuildInto(t, blobDir, bootstrap, fixture.Corpus(t, fixture.Seeded), layout)

			// A native blob is a raw EROFS device with no blob meta region.
			f := readFooter(t, blob)
			require.Equal(t, layout.Native, f.rawDevice(), "RAW_DEVICE footer feature")
			if layout.Native {
				require.Zero(t, f.MetaSize, "blob meta region of a native blob")
			} else {
				require.NotZero(t, f.MetaSize, "blob meta region")
			}

			tags, err := oracle.ErofsDeviceTags(bootstrap)
			require.NoError(t, err)
			require.Equal(t, []string{filepath.Base(blob)}, tags, "device table")

			if fsckDecodes(t, layout) {
				oracle.FsckErofs(t, bootstrap, blobDir)
			}

			requireVerified(t, bootstrap, blobDir, []string{blob})
			report, err := nydusCheck(t, "--blob", blob)
			require.NoError(t, err)
			require.Equal(t, "blob", report.Kind)
			require.Len(t, report.Blobs, 1)
			if !layout.Native {
				require.True(t, report.Blobs[0].Verified, "the data region of %s does not match its slot", blob)
			}

			// The fixture cache was built by another build of the same
			// binary from the same tree, possibly in another process.
			cached := fixture.Get(t, layout.Name)
			require.Equal(t, fileSHA256(t, cached.Bootstrap), fileSHA256(t, bootstrap), "bootstrap differs from the cached build")
			require.Equal(t, filepath.Base(cached.Blob()), filepath.Base(blob), "blob differs from the cached build")
		})
	}
}
