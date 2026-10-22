package nydusify

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

// TestConvert converts single- and multi-layer OCI images with every nydus
// compressor, pulls the result and reads it with the FUSE reader: one blob
// layer per source layer plus the bootstrap layer, reproducing the overlay
// of the source layers.
func TestConvert(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)
	for _, src := range corpusSources(t) {
		srcRef := reg.Ref("convert-"+src.name, "oci")
		reg.PushDirs(t, srcRef, src.dirs...)
		for _, compressor := range []string{"zstd", "lz4", "none", "erofs-none", "erofs-lz4", "erofs-zstd"} {
			t.Run(src.name+"/"+compressor, func(t *testing.T) {
				t.Parallel()
				target := reg.Ref("convert-"+src.name, compressor)
				nydusify(t, "convert", "--source", srcRef, "--target", target, "--compressor", compressor)

				img := pullNydus(t, target, src.want)
				require.Len(t, img.Blobs, len(src.dirs), "one blob per source layer")
				m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
				oracle.VerifyMount(t, m.Root, src.want, src.compare())
			})
		}
	}
}
