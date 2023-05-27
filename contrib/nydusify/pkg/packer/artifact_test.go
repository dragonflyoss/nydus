package packer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifactPath(t *testing.T) {
	artifact, err := NewArtifact("/tmp")

	assert.Nil(t, err)
	assert.Equal(t, artifact.bootstrapPath("test.meta"), "/tmp/test.meta")
	assert.Equal(t, artifact.bootstrapPath("test.m"), "/tmp/test.m")
	assert.Equal(t, artifact.bootstrapPath("test"), "/tmp/test.meta")
	assert.Equal(t, artifact.blobFilePath("test.meta", false), "/tmp/test.blob")
	assert.Equal(t, artifact.blobFilePath("test.m", false), "/tmp/test.blob")
	assert.Equal(t, artifact.blobFilePath("test", false), "/tmp/test.blob")
	assert.Equal(t, artifact.blobFilePath("test", true), "/tmp/test")
}
