package packer

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockBackend struct {
	mock.Mock
}

func (m *mockBackend) Upload(ctx context.Context, blobID, blobPath string, blobSize int64, forcePush bool) (*ocispec.Descriptor, error) {
	args := m.Called(ctx, blobID, blobPath, blobSize, forcePush)
	desc := args.Get(0)
	return desc.(*ocispec.Descriptor), nil
}

func (m *mockBackend) Finalize(cancel bool) error {
	return nil
}

func (m *mockBackend) Check(_ string) (bool, error) {
	return false, nil
}

func (m *mockBackend) Type() backend.Type {
	return backend.OssBackend
}

func Test_parseBackendConfig(t *testing.T) {
	cfg, err := ParseBackendConfig(filepath.Join("testdata", "backend-config.json"))
	assert.Nil(t, err)
	assert.Equal(t, BackendConfig{
		Endpoint:        "mock.aliyuncs.com",
		AccessKeyID:     "testid",
		AccessKeySecret: "testkey",
		BucketName:      "testbucket",
		MetaPrefix:      "test",
		BlobPrefix:      "",
	}, cfg)
}

func Test_parseBackendConfigString(t *testing.T) {
	cfg, err := ParseBackendConfigString(`{
  "endpoint": "mock.aliyuncs.com",
  "access_key_id": "testid",
  "access_key_secret": "testkey",
  "bucket_name": "testbucket",
  "meta_prefix": "test/",
  "blob_prefix": ""
}`)
	assert.Nil(t, err)
	assert.Equal(t, BackendConfig{
		Endpoint:        "mock.aliyuncs.com",
		AccessKeyID:     "testid",
		AccessKeySecret: "testkey",
		BucketName:      "testbucket",
		MetaPrefix:      "test",
		BlobPrefix:      "",
	}, cfg)
}

func TestPusher_Push(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()

	os.Create(filepath.Join(tmpDir, "mock.meta"))
	os.Create(filepath.Join(tmpDir, "mock.blob"))
	content, _ := ioutil.ReadFile(filepath.Join("testdata", "output.json"))
	ioutil.WriteFile(filepath.Join(tmpDir, "output.json"), content, 0755)

	artifact, err := NewArtifact(tmpDir)
	assert.Nil(t, err)
	mp := &mockBackend{}
	pusher := Pusher{
		Artifact: artifact,
		cfg: BackendConfig{
			BucketName: "testbucket",
			BlobPrefix: "testblobprefix",
			MetaPrefix: "testmetaprefix",
		},
		logger:      logrus.New(),
		metaBackend: mp,
		blobBackend: mp,
	}

	hash := "3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090"
	assert.Nil(t, err)
	mp.On("Upload", mock.Anything, "mock.meta", mock.Anything, mock.Anything, mock.Anything).Return(&ocispec.Descriptor{
		URLs: []string{"oss://testbucket/testmetaprefix/mock.meta"},
	}, nil)
	mp.On("Upload", mock.Anything, hash, mock.Anything, mock.Anything, mock.Anything).Return(&ocispec.Descriptor{
		URLs: []string{"oss://testbucket/testblobprefix/3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090"},
	}, nil)
	res, err := pusher.Push(PushRequest{
		Meta: "mock.meta",
		Blob: hash,
	})
	assert.Nil(t, err)
	assert.Equal(
		t,
		PushResult{
			RemoteMeta: "oss://testbucket/testmetaprefix/mock.meta",
			RemoteBlob: "oss://testbucket/testblobprefix/3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090",
		},
		res,
	)
}
