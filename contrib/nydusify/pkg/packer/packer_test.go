package packer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/build"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockBuilder struct {
	mock.Mock
}

func (m *mockBuilder) Run(option build.BuilderOption) error {
	args := m.Called(option)
	return args.Error(0)
}

func TestNew(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()
	_, err := New(Opt{
		LogLevel:       logrus.InfoLevel,
		OutputDir:      tmpDir,
		NydusImagePath: filepath.Join(tmpDir, "nydus-image"),
	})
	assert.Nil(t, err)
}

func copyFile(src, dst string) {
	f1, err := os.Open(src)
	if err != nil {
		return
	}
	defer f1.Close()
	f2, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer f2.Close()
	io.Copy(f2, f1)
}

func TestPacker_Pack(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()
	p, err := New(Opt{
		LogLevel:       logrus.InfoLevel,
		OutputDir:      tmpDir,
		NydusImagePath: filepath.Join(tmpDir, "nydus-image"),
	})
	copyFile("testdata/output.json", filepath.Join(tmpDir, "output.json"))
	assert.Nil(t, err)
	builder := &mockBuilder{}
	p.builder = builder
	builder.On("Run", mock.Anything).Return(nil)
	res, err := p.Pack(context.Background(), PackRequest{
		SourceDir:    tmpDir,
		ImageName:    "test.meta",
		PushToRemote: false,
	})
	assert.Nil(t, err)
	assert.Equal(t, PackResult{
		Meta: "testdata/TestPacker_Pack/test.meta",
		Blob: "testdata/TestPacker_Pack/test.blob",
	}, res)

}

func TestPusher_getBlobHash(t *testing.T) {
	artifact, err := NewArtifact("testdata")
	assert.Nil(t, err)
	pusher := Packer{
		Artifact: artifact,
		logger:   logrus.New(),
	}
	hash, err := pusher.getNewBlobsHash(nil)
	assert.Nil(t, err)
	assert.Equal(t, "3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090", hash)
}

func setUpTmpDir(t *testing.T) (string, func()) {
	tmpDir := filepath.Join("testdata", t.Name())
	os.MkdirAll(tmpDir, 0755)
	file, _ := os.Create(filepath.Join(tmpDir, "nydus-image"))
	file.Write([]byte("for test"))
	file.Close()
	return tmpDir, func() {
		os.RemoveAll(tmpDir)
	}
}
