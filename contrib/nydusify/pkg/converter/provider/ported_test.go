package provider

import (
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestImageName(t *testing.T) {
	require.Equal(t,
		"docker.io/library/busybox:latest",
		imageName(map[string]string{images.AnnotationImageName: "docker.io/library/busybox:latest"}, nil),
	)

	require.Equal(t,
		"cleaned:tag",
		imageName(map[string]string{ocispec.AnnotationRefName: "raw:tag"}, func(ref string) string {
			require.Equal(t, "raw:tag", ref)
			return "cleaned:tag"
		}),
	)

	require.Equal(t, "", imageName(nil, nil))
}
