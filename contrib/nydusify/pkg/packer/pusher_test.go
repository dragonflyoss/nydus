package packer

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockPusher struct {
	mock.Mock
}

func (m *mockPusher) PutObject(s string, reader io.Reader, option ...oss.Option) error {
	args := m.Called(s, reader, option)
	return args.Error(0)
}

func Test_parseBackendConfig(t *testing.T) {
	cfg, err := ParseBackendConfig(filepath.Join("testdata", "backend-config.json"))
	assert.Nil(t, err)
	assert.Equal(t, BackendConfig{
		Endpoint:        "mock.aliyuncs.com",
		AccessKeyId:     "testid",
		AccessKeySecret: "testkey",
		BucketName:      "testbucket",
		MetaPrefix:      "test",
		BlobPrefix:      "",
	}, cfg)
}

func TestPusher_getBlobHash(t *testing.T) {
	artifact, err := NewArtifact("testdata")
	assert.Nil(t, err)
	pusher := Pusher{
		Artifact: artifact,
		cfg:      BackendConfig{},
		logger:   logrus.New(),
	}
	hash, err := pusher.getBlobHash()
	assert.Nil(t, err)
	assert.Equal(t, "3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090", hash)
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
	mp := &mockPusher{}
	pusher := Pusher{
		Artifact: artifact,
		cfg: BackendConfig{
			BucketName: "testbucket",
			BlobPrefix: "testblobprefix",
			MetaPrefix: "testmetaprefix",
		},
		logger: logrus.New(),
		bucket: mp,
	}

	hash, err := pusher.getBlobHash()
	assert.Nil(t, err)
	mp.On("PutObject", "testmetaprefix/mock.meta", mock.Anything, mock.Anything).Return(nil)
	mp.On("PutObject", fmt.Sprintf("testblobprefix/%s", hash), mock.Anything, mock.Anything).Return(nil)
	res, err := pusher.Push(PushRequest{
		Meta: "mock.meta",
		Blob: "mock.blob",
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
