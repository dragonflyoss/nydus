package packer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/build"
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

func Test_blobFileName(t *testing.T) {
	blob := blobFileName("system.meta")
	assert.Equal(t, "system.blob", blob)
}

func TestNew(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()
	_, err := New(Opt{
		LogLevel:  "info",
		OutputDir: tmpDir,
	})
	assert.Nil(t, err)
}

func TestPacker_Pack(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()
	p, err := New(Opt{
		LogLevel:  "info",
		OutputDir: tmpDir,
	})
	assert.Nil(t, err)
	builder := &mockBuilder{}
	p.builder = builder
	builder.On("Run", mock.Anything).Return(nil)
	res, err := p.Pack(context.Background(), PackRequest{
		TargetDir: tmpDir,
		Meta:      "test.meta",
		PushBlob:  false,
	})
	assert.Nil(t, err)
	assert.Equal(t, PackResult{
		Meta: "testdata/TestPacker_Pack/test.meta",
		Blob: "testdata/TestPacker_Pack/test.blob",
	}, res)

}

func setUpTmpDir(t *testing.T) (string, func()) {
	tmpDir := filepath.Join("testdata", t.Name())
	os.MkdirAll(tmpDir, 0755)
	return tmpDir, func() {
		os.RemoveAll(tmpDir)
	}
}
