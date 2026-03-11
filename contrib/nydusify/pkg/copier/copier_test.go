package copier

import (
	"path/filepath"
	"testing"

	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestGetPlatform(t *testing.T) {
	require.Equal(t, platforms.DefaultString(), getPlatform(nil))
	require.Equal(t, "linux/arm64", getPlatform(&ocispec.Platform{OS: "linux", Architecture: "arm64"}))
	require.Equal(t, "windows/amd64", getPlatform(&ocispec.Platform{OS: "windows", Architecture: "amd64"}))
}

func TestGetLocalPath(t *testing.T) {
	isLocal, absPath, err := getLocalPath("docker.io/library/busybox:latest")
	require.NoError(t, err)
	require.False(t, isLocal)
	require.Empty(t, absPath)

	isLocal, absPath, err = getLocalPath("file://./testdata")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.Equal(t, filepath.Join(filepath.Dir(absPath), "testdata"), absPath)

	isLocal, absPath, err = getLocalPath("file:///tmp/image.tar")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.Equal(t, "/tmp/image.tar", absPath)
}
