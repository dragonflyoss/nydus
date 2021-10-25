package converter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImageRepository(t *testing.T) {
	ref1 := "docker.io/library/busybox:latest"
	repo, err := imageRepository(ref1)

	assert.Nil(t, err)
	assert.Equal(t, "docker.io/library/busybox", repo)

	ref2 := "docker.io/library/busybox@sha256:7cc4b5aefd1d0cadf8d97d4350462ba51c694ebca145b08d7d41b41acc8db5aa"
	repo, err = imageRepository(ref2)

	assert.Nil(t, err)
	assert.Equal(t, "docker.io/library/busybox", repo)

	ref3 := "https://docker.io/library/busybox:latest"
	repo, err = imageRepository(ref3)

	assert.NotNil(t, err)
	assert.Equal(t, "", repo)

	ref4 := "busybox:latest"
	repo, err = imageRepository(ref4)

	assert.Nil(t, err)
	assert.Equal(t, "docker.io/library/busybox", repo)

	ref5 := "ghcr.io/busybox:latest"
	repo, err = imageRepository(ref5)

	assert.Nil(t, err)
	assert.Equal(t, "ghcr.io/busybox", repo)

	ref6 := "ghcr.io/nydus/busybox:latest"
	repo, err = imageRepository(ref6)

	assert.Nil(t, err)
	assert.Equal(t, "ghcr.io/nydus/busybox", repo)
}
