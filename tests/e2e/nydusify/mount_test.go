package nydusify

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

// TestMount runs `nydusify mount`: a nydus image is served by FUSE on
// demand from the registry, with metrics on the apiserver under the work
// directory; an OCI image is extracted into the mountpoint instead. Both
// reproduce the source tree.
func TestMount(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)
	for _, src := range corpusSources(t) {
		t.Run(src.name, func(t *testing.T) {
			t.Parallel()
			srcRef := reg.Ref("mount-"+src.name, "oci")
			nydusRef := reg.Ref("mount-"+src.name, "nydus")
			reg.PushDirs(t, srcRef, src.dirs...)
			nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)

			manifest, err := remoteImage(t, nydusRef).Manifest()
			require.NoError(t, err)
			dataBlobs := map[string]bool{}
			for _, layer := range manifest.Layers {
				if _, ok := layer.Annotations[nydusBlobAnnotation]; ok {
					dataBlobs[layer.Digest.String()] = true
				}
			}
			require.NotEmpty(t, dataBlobs)
			before := len(reg.Faults.Requests())
			_, mnt, api := startMount(t, nydusRef, false)
			for _, request := range reg.Faults.Requests()[before:] {
				_, digest, _ := strings.Cut(request.Path, "/blobs/")
				require.False(t, request.Method == http.MethodGet && strings.HasPrefix(request.Path, "/v2/mount-"+src.name+"/blobs/") && dataBlobs[digest],
					"mount downloaded data before the first read: %+v", request)
			}
			oracle.VerifyMount(t, mnt, src.want, src.compare())
			metrics := api.Metrics(t)
			require.Positive(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`), "reads must be served on demand from the registry")
			require.Zero(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`), "prefetch is off by default")

			oracle.VerifyMount(t, extractOCI(t, srcRef), src.want, src.compare())
		})
	}
}
