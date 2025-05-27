// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package packer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
)

type mockBackend struct {
	mock.Mock
}

func (m *mockBackend) Upload(ctx context.Context, blobID, blobPath string, blobSize int64, forcePush bool) (*ocispec.Descriptor, error) {
	args := m.Called(ctx, blobID, blobPath, blobSize, forcePush)
	desc := args.Get(0)
	return desc.(*ocispec.Descriptor), nil
}

func (m *mockBackend) Finalize(_ bool) error {
	return nil
}

func (m *mockBackend) Check(_ string) (bool, error) {
	return false, nil
}

func (m *mockBackend) Type() backend.Type {
	return backend.OssBackend
}

func (m *mockBackend) Reader(_ string) (io.ReadCloser, error) {
	panic("not implemented")
}

func (m *mockBackend) RangeReader(_ string) (remotes.RangeReadCloser, error) {
	panic("not implemented")
}

func (m *mockBackend) Size(_ string) (int64, error) {
	panic("not implemented")
}

func Test_parseBackendConfig(t *testing.T) {
	cfg, err := ParseBackendConfig("oss", filepath.Join("testdata", "backend-config.json"))
	require.NoError(t, err)
	require.Equal(t, &OssBackendConfig{
		Endpoint:        "mock.aliyuncs.com",
		AccessKeyID:     "testid",
		AccessKeySecret: "testkey",
		BucketName:      "testbucket",
		MetaPrefix:      "test/",
		BlobPrefix:      "",
	}, cfg)
}

func Test_parseBackendConfigString(t *testing.T) {
	cfg, err := ParseBackendConfigString("oss", `
	{
		"endpoint": "mock.aliyuncs.com",
		"access_key_id": "testid",
		"access_key_secret": "testkey",
		"bucket_name": "testbucket",
		"meta_prefix": "test/",
		"blob_prefix": ""
	}`)
	require.NoError(t, err)
	require.Equal(t, &OssBackendConfig{
		Endpoint:        "mock.aliyuncs.com",
		AccessKeyID:     "testid",
		AccessKeySecret: "testkey",
		BucketName:      "testbucket",
		MetaPrefix:      "test/",
		BlobPrefix:      "",
	}, cfg)

	cfg, err = ParseBackendConfigString("s3", `
	{
		"bucket_name": "test",
		"endpoint": "s3.amazonaws.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob",
		"scheme": "https",
		"region": "region1",
		"meta_prefix": "meta/",
		"blob_prefix": "blob/"
	}`)
	require.NoError(t, err)
	require.Equal(t, &S3BackendConfig{
		Endpoint:        "s3.amazonaws.com",
		AccessKeyID:     "testAK",
		AccessKeySecret: "testSK",
		BucketName:      "test",
		Scheme:          "https",
		Region:          "region1",
		MetaPrefix:      "meta/",
		BlobPrefix:      "blob/",
	}, cfg)

	cfg, err = ParseBackendConfigString("registry", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported backend type")
	require.Empty(t, cfg)
}

func TestPusher_Push(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()

	os.Create(filepath.Join(tmpDir, "mock.meta"))
	os.Create(filepath.Join(tmpDir, "mock.blob"))
	content, _ := os.ReadFile(filepath.Join("testdata", "output.json"))
	os.WriteFile(filepath.Join(tmpDir, "output.json"), content, 0755)

	artifact, err := NewArtifact(tmpDir)
	require.NoError(t, err)

	mp := &mockBackend{}
	pusher := Pusher{
		Artifact: artifact,
		cfg: &OssBackendConfig{
			BucketName: "testbucket",
			BlobPrefix: "testblobprefix",
			MetaPrefix: "testmetaprefix",
		},
		logger:      logrus.New(),
		metaBackend: mp,
		blobBackend: mp,
	}
	hash := "3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090"
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
	require.NoError(t, err)
	require.Equal(
		t,
		PushResult{
			RemoteMeta: "oss://testbucket/testmetaprefix/mock.meta",
			RemoteBlob: "oss://testbucket/testblobprefix/3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090",
		},
		res,
	)
}

func TestNewPusher(t *testing.T) {
	backendConfig := &OssBackendConfig{
		Endpoint:   "region.oss.com",
		BucketName: "testbucket",
		BlobPrefix: "testblobprefix",
		MetaPrefix: "testmetaprefix",
	}
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()

	artifact, err := NewArtifact(tmpDir)
	require.NoError(t, err)
	_, err = NewPusher(NewPusherOpt{
		Artifact:      artifact,
		BackendConfig: backendConfig,
		Logger:        logrus.New(),
	})
	require.NoError(t, err)

	_, err = NewPusher(NewPusherOpt{
		BackendConfig: backendConfig,
		Logger:        logrus.New(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outputDir is required")

	_, err = NewPusher(NewPusherOpt{
		Artifact:      Artifact{OutputDir: "test"},
		BackendConfig: backendConfig,
		Logger:        logrus.New(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exists")

	_, err = NewPusher(NewPusherOpt{
		Artifact: artifact,
		BackendConfig: &OssBackendConfig{
			BucketName: "testbucket",
			BlobPrefix: "testblobprefix",
			MetaPrefix: "testmetaprefix",
		},
		Logger: logrus.New(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to init backend for bootstrap blob")
}
