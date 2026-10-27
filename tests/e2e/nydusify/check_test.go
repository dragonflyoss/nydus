package nydusify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

// TestCheck runs `nydusify check` on converted images: against their OCI
// source it passes for chunk-based and native layers alike (manifest,
// bootstrap and a full filesystem diff), it fails on an image of different
// content, and on a single image it exports exactly what the registry holds.
func TestCheck(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)
	srcs := corpusSources(t)
	refs := map[string]string{}
	for _, src := range srcs {
		refs[src.name] = reg.Ref("check-"+src.name, "oci")
		reg.PushDirs(t, refs[src.name], src.dirs...)
	}

	for _, src := range srcs {
		for _, compressor := range []string{"zstd", "erofs-lz4"} {
			t.Run(src.name+"/"+compressor, func(t *testing.T) {
				t.Parallel()
				target := reg.Ref("check-"+src.name, compressor)
				nydusify(t, "convert", "--source", refs[src.name], "--target", target, "--compressor", compressor)
				nydusify(t, "check", "--source", refs[src.name], "--target", target)

				work := t.TempDir()
				nydusify(t, "check", "--target", target, "--work-dir", work)
				exported, err := os.ReadFile(filepath.Join(work, "target", "manifest.json"))
				require.NoError(t, err)
				remoteImg := remoteImage(t, target)
				raw, err := remoteImg.RawManifest()
				require.NoError(t, err)
				require.Equal(t, string(raw), string(exported), "exported manifest")
				exported, err = os.ReadFile(filepath.Join(work, "target", "config.json"))
				require.NoError(t, err)
				raw, err = remoteImg.RawConfigFile()
				require.NoError(t, err)
				require.Equal(t, string(raw), string(exported), "exported config")
				pulled := pullNydus(t, target, src.want)
				require.Equal(t, fileSHA256(t, pulled.Bootstrap),
					fileSHA256(t, filepath.Join(work, "target", "bootstrap", bootstrapInLayer)), "exported bootstrap")
			})
		}
	}

	t.Run("Mismatch", func(t *testing.T) {
		t.Parallel()
		target := reg.Ref("check-single", "mismatch")
		nydusify(t, "convert", "--source", refs["single"], "--target", target)
		out, err := tryNydusify(t, "check", "--source", refs["multi"], "--target", target)
		require.Error(t, err, "an image checked against another image's source must fail:\n%s", out)
	})
}
