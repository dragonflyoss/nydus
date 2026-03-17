package committer

import (
	"errors"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestWithRetry(t *testing.T) {
	attempts := 0
	err := withRetry(func() error {
		attempts++
		if attempts < 3 {
			return errors.New("retry")
		}
		return nil
	}, 3)
	require.NoError(t, err)
	require.Equal(t, 3, attempts)

	attempts = 0
	err = withRetry(func() error {
		attempts++
		return errors.New("still failing")
	}, 2)
	require.EqualError(t, err, "still failing")
	require.Equal(t, 2, attempts)
}

func TestValidateRef(t *testing.T) {
	ref, err := ValidateRef("nginx:latest")
	require.NoError(t, err)
	require.Equal(t, "docker.io/library/nginx:latest", ref)

	ref, err = ValidateRef("localhost:5000/ns/image")
	require.NoError(t, err)
	require.Equal(t, "localhost:5000/ns/image:latest", ref)

	_, err = ValidateRef("bad\nref")
	require.ErrorContains(t, err, "invalid image reference")

	_, err = ValidateRef("docker.io/library/nginx:latest@sha256:757574c5a2102627de54971a0083d4ecd24eb48fdf06b234d063f19f7bbc22fb")
	require.ErrorContains(t, err, "unsupported digested image reference")
}

func TestGetDistributionSourceLabel(t *testing.T) {
	key, value := getDistributionSourceLabel("docker.io/library/busybox:latest")
	require.Equal(t, "containerd.io/distribution.source.docker.io", key)
	require.Equal(t, "library/busybox", value)

	key, value = getDistributionSourceLabel("busybox:latest")
	require.Equal(t, "containerd.io/distribution.source.docker.io", key)
	require.Equal(t, "library/busybox", value)
}

func TestMountList(t *testing.T) {
	ml := NewMountList()
	require.NotNil(t, ml)
	require.Empty(t, ml.paths)

	ml.Add("/mnt/a")
	ml.Add("/mnt/b")
	require.Equal(t, []string{"/mnt/a", "/mnt/b"}, ml.paths)
}

func TestMakeDesc(t *testing.T) {
	cm := &Committer{}
	data := map[string]string{"key": "val"}
	oldDesc := ocispec.Descriptor{MediaType: "application/json"}

	bytes, desc, err := cm.makeDesc(data, oldDesc)
	require.NoError(t, err)
	require.NotNil(t, bytes)
	require.NotNil(t, desc)
	require.Equal(t, "application/json", desc.MediaType)
	require.Greater(t, desc.Size, int64(0))
	require.NotEmpty(t, desc.Digest)
}

func TestWithRetryImmediate(t *testing.T) {
	err := withRetry(func() error { return nil }, 1)
	require.NoError(t, err)
}

func TestValidateRefAddsTag(t *testing.T) {
	ref, err := ValidateRef("example.com/repo")
	require.NoError(t, err)
	require.Contains(t, ref, ":latest")
}

func TestGetDistributionSourceLabelInvalid(t *testing.T) {
	key, value := getDistributionSourceLabel("bad\nref")
	require.Empty(t, key)
	require.Empty(t, value)
}

func TestMakeDescMarshalError(t *testing.T) {
	cm := &Committer{}
	badData := make(chan int)
	_, _, err := cm.makeDesc(badData, ocispec.Descriptor{})
	require.Error(t, err)
}
