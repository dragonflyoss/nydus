package backend

import (
	"context"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func TestRegistryUpload(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "blob-*")
	require.NoError(t, err)
	_, err = tmp.WriteString("blob-data")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	registry := &Registry{remote: &remote.Remote{}}
	patches := gomonkey.ApplyMethod(reflect.TypeOf(&remote.Remote{}), "Push", func(_ *remote.Remote, _ context.Context, desc ocispec.Descriptor, byDigest bool, reader io.Reader) error {
		require.True(t, byDigest)
		require.Equal(t, utils.MediaTypeNydusBlob, desc.MediaType)
		require.Equal(t, digest.Digest("sha256:205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a"), desc.Digest)
		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.Equal(t, "blob-data", string(content))
		return nil
	})
	defer patches.Reset()

	desc, err := registry.Upload(context.Background(), "205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a", tmp.Name(), 8, false)
	require.NoError(t, err)
	require.Equal(t, int64(8), desc.Size)
	require.Equal(t, utils.MediaTypeNydusBlob, desc.MediaType)
	assertAnnotations := map[string]string{
		utils.LayerAnnotationUncompressed: "sha256:205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a",
		utils.LayerAnnotationNydusBlob:    "true",
	}
	require.Equal(t, assertAnnotations, desc.Annotations)
}

func TestRegistryUploadFailuresAndHelpers(t *testing.T) {
	registry := &Registry{remote: &remote.Remote{}}

	_, err := registry.Upload(context.Background(), "205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a", "/non-existent", 1, false)
	require.ErrorContains(t, err, "Open blob file")

	tmp, err := os.CreateTemp(t.TempDir(), "blob-*")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&remote.Remote{}), "Push", func(_ *remote.Remote, _ context.Context, _ ocispec.Descriptor, _ bool, _ io.Reader) error {
		return io.EOF
	})
	defer patches.Reset()

	_, err = registry.Upload(context.Background(), "205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a", tmp.Name(), 0, false)
	require.ErrorContains(t, err, "Push blob layer")

	require.NoError(t, registry.Finalize(false))
	ok, err := registry.Check("ignored")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, RegistryBackend, registry.Type())
}
