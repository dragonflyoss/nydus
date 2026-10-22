package nydusify

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func TestPublishRecovery(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	for _, stage := range []string{"blob", "manifest", "eager"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			reg := registry.Start(t)
			src := inputTree(t, map[string]string{"payload": strings.Repeat("publish recovery\n", 8192)})
			source, target := reg.Ref("source", "oci"), reg.Ref("target", "nydus")
			reg.PushDirs(t, source, src)
			times := 0
			if stage == "eager" {
				times = 1
			}
			reg.Faults.Set(registry.Fault{Status: http.StatusForbidden, Times: times, Match: func(r *http.Request) bool {
				if !strings.HasPrefix(r.URL.Path, "/v2/target/") {
					return false
				}
				if stage != "manifest" {
					return r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/")
				}
				return r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/")
			}})
			work := t.TempDir()
			args := []string{"convert", "--source", source, "--target", target, "--work-dir", work}
			out, err := tryNydusify(t, args...)
			require.Positive(t, reg.Faults.Hits(), "publish never reached the fault")
			if stage == "eager" {
				require.NoError(t, err, "%s", out)
				require.Contains(t, out, "eager blob push", "the best-effort push must fail before final publication recovers")
			} else {
				require.Error(t, err, "%s", out)
				ref, err := name.ParseReference(target, name.Insecure)
				require.NoError(t, err)
				_, err = remote.Head(ref)
				require.Error(t, err, "failed publication must not expose a manifest")
				reg.Faults.Clear()
				nydusify(t, args...)
			}
			img := pullNydus(t, target, oracle.ScanSource(t, src))
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
			oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	}
}
