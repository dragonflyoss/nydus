package converter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	snapConv "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/converter"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/stretchr/testify/assert"
)

func TestConvertModelFile(t *testing.T) {
	opt := Opt{
		WorkDir:           "/tmp/nydusify",
		SourceBackendType: "{}",
		ChunkSize:         "4MiB",
	}
	err := convertModelFile(context.Background(), opt)
	assert.Error(t, err)
}

func TestConvertModelArtifact(t *testing.T) {
	opt := Opt{
		WorkDir: "/tmp/nydusify",
	}
	err := convertModelArtifact(context.Background(), opt)
	assert.Error(t, err)
}

func TestPackWithAttributes(t *testing.T) {
	packOpt := snapConv.PackOption{
		BuilderPath: "/tmp/nydus-image",
	}
	blobDir := "/tmp/nydusify"
	os.MkdirAll(blobDir, 0755)
	defer os.RemoveAll(blobDir)
	_, _, err := packWithAttributes(context.Background(), packOpt, blobDir)
	assert.Nil(t, err)
}

func TestPackFinalBootstrap(t *testing.T) {
	workDir := "/tmp/nydusify"
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)
	cfgPath := filepath.Join(workDir, "backend.json")
	os.Create(cfgPath)
	extDigest := digest.FromString("abc1234")
	_, err := packFinalBootstrap(workDir, cfgPath, extDigest)
	assert.Error(t, err)
}

func TestBuildNydusImage(t *testing.T) {
	image := buildNydusImage()
	assert.NotNil(t, image)
}

func TestMakeDesc(t *testing.T) {
	input := "test"
	oldDesc := ocispec.Descriptor{
		MediaType: "test",
	}
	_, _, err := makeDesc(input, oldDesc)
	assert.NoError(t, err)
}
