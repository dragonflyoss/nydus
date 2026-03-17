// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package packer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/build"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	_, err = New(Opt{
		LogLevel:  logrus.InfoLevel,
		OutputDir: tmpDir,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to find nydus-image binary")

	_, err = New(Opt{
		LogLevel:       logrus.InfoLevel,
		OutputDir:      "nil",
		NydusImagePath: "nil/nydus-image",
	})
	defer os.RemoveAll("nil")
	if _, find := exec.LookPath("nydus-image"); find == nil {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find nydus-image binary")
	}

	_, err = New(Opt{
		LogLevel:       logrus.InfoLevel,
		OutputDir:      tmpDir,
		NydusImagePath: filepath.Join(tmpDir, "nydus-image"),
		BackendConfig: &S3BackendConfig{
			Endpoint:        "s3.amazonaws.com",
			Scheme:          "https",
			AccessKeyID:     "testAK",
			AccessKeySecret: "testSK",
			Region:          "region1",
			BucketName:      "test",
			MetaPrefix:      "meta",
			BlobPrefix:      "blob",
		},
	})
	require.NoError(t, err)
}

func TestDumpBlobBackendConfig(t *testing.T) {
	os.MkdirAll(t.Name(), 0755)
	defer os.RemoveAll(t.Name())
	file, _ := os.Create(filepath.Join(t.Name(), "nydus-image"))
	file.Write([]byte("for test"))
	file.Close()

	p, err := New(Opt{
		OutputDir:      t.Name(),
		NydusImagePath: filepath.Join(t.Name(), "nydus-image"),
		BackendConfig: &S3BackendConfig{
			Endpoint:        "s3.amazonaws.com",
			Scheme:          "https",
			AccessKeyID:     "testAK",
			AccessKeySecret: "testSK",
			Region:          "region1",
			BucketName:      "test",
			MetaPrefix:      "meta",
			BlobPrefix:      "blob",
		},
	})
	require.NoError(t, err)

	_, err = p.dumpBlobBackendConfig(filepath.Join(t.Name(), "test.json"))
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(t.Name(), "test.json"))
	require.NoError(t, err)
	require.Equal(t, p.BackendConfig.rawBlobBackendCfg(), data)
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

func TestPack(t *testing.T) {
	tmpDir, tearDown := setUpTmpDir(t)
	defer tearDown()
	p, err := New(Opt{
		LogLevel:       logrus.InfoLevel,
		OutputDir:      tmpDir,
		NydusImagePath: filepath.Join(tmpDir, "nydus-image"),
	})
	copyFile("testdata/output.json", filepath.Join(tmpDir, "output.json"))
	require.NoError(t, err)

	builder := &mockBuilder{}
	p.builder = builder
	builder.On("Run", mock.Anything).Return(nil)
	res, err := p.Pack(context.Background(), PackRequest{
		SourceDir:    tmpDir,
		ImageName:    "test.meta",
		PushToRemote: false,
	})
	require.NoError(t, err)
	require.Equal(t, PackResult{
		Meta: "testdata/TestPack/test.meta",
		Blob: "testdata/TestPack/test.blob",
	}, res)

	errBuilder := &mockBuilder{}
	p.builder = errBuilder
	errBuilder.On("Run", mock.Anything).Return(errors.New("test"))
	res, err = p.Pack(context.Background(), PackRequest{
		SourceDir:    tmpDir,
		ImageName:    "test.meta",
		PushToRemote: false,
	})
	require.Error(t, err)
	require.Empty(t, res)

	os.Create(filepath.Join(tmpDir, "test.meta"))
	os.Create(filepath.Join(tmpDir, "test.blob"))

	p.builder = builder
	_, err = p.Pack(context.Background(), PackRequest{
		SourceDir:    tmpDir,
		ImageName:    "test.meta",
		PushToRemote: true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "can not push image to remote due to lack of backend configuration")

	os.Create(filepath.Join(tmpDir, "test.meta"))
	os.Create(filepath.Join(tmpDir, "test.blob"))
	artifact, err := NewArtifact(tmpDir)
	require.NoError(t, err)
	mp := &mockBackend{}
	p.pusher = &Pusher{
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

	mp.On("Upload", mock.Anything, "test.meta", mock.Anything, mock.Anything, mock.Anything).Return(&ocispec.Descriptor{
		URLs: []string{"oss://testbucket/testmetaprefix/test.meta"},
	}, nil)
	mp.On("Upload", mock.Anything, hash, mock.Anything, mock.Anything, mock.Anything).Return(&ocispec.Descriptor{
		URLs: []string{"oss://testbucket/testblobprefix/3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090"},
	}, nil)

	res, err = p.Pack(context.Background(), PackRequest{
		SourceDir:    tmpDir,
		ImageName:    "test.meta",
		PushToRemote: true,
	})
	require.NoError(t, err)
	require.Equal(t, PackResult{
		Meta: "oss://testbucket/testmetaprefix/test.meta",
		Blob: "oss://testbucket/testblobprefix/3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090",
	}, res)
}

func TestPusher_getBlobHash(t *testing.T) {
	artifact, err := NewArtifact("testdata")
	require.NoError(t, err)
	pusher := Packer{
		Artifact: artifact,
		logger:   logrus.New(),
	}
	hash, err := pusher.getNewBlobsHash(nil)
	require.NoError(t, err)
	require.Equal(t, "3093776c78a21e47f0a8b4c80a1f019b1e838fc1ade274209332af1ca5f57090", hash)
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

func TestGetChunkDictBlobsEmpty(t *testing.T) {
	p := &Packer{logger: logrus.New()}
	blobs, err := p.getChunkDictBlobs("")
	require.NoError(t, err)
	require.Empty(t, blobs)
}

func TestGetChunkDictBlobsInvalidFormat(t *testing.T) {
	p := &Packer{logger: logrus.New()}
	_, err := p.getChunkDictBlobs("no-equals-sign")
	require.ErrorIs(t, err, ErrInvalidChunkDictArgs)
}

func TestGetChunkDictBlobsTooManyParts(t *testing.T) {
	p := &Packer{logger: logrus.New()}
	_, err := p.getChunkDictBlobs("a=b=c")
	require.ErrorIs(t, err, ErrInvalidChunkDictArgs)
}

func TestGetChunkDictBlobsUnsupportedType(t *testing.T) {
	p := &Packer{logger: logrus.New()}
	_, err := p.getChunkDictBlobs("blob=/tmp/file")
	require.ErrorIs(t, err, ErrNoSupport)
}

func TestTryCompactParentSkips(t *testing.T) {
	p := &Packer{logger: logrus.New()}

	t.Run("compact disabled", func(t *testing.T) {
		req := &PackRequest{TryCompact: false, Parent: "/some/parent"}
		require.NoError(t, p.tryCompactParent(req))
	})

	t.Run("no parent", func(t *testing.T) {
		req := &PackRequest{TryCompact: true, Parent: ""}
		require.NoError(t, p.tryCompactParent(req))
	})

	t.Run("no backend config", func(t *testing.T) {
		req := &PackRequest{TryCompact: true, Parent: "/some/parent"}
		err := p.tryCompactParent(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "backend configuration is needed")
	})
}

func TestEnsureNydusImagePathErrors(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		p := &Packer{logger: logrus.New(), nydusImagePath: ""}
		err := p.ensureNydusImagePath()
		require.ErrorIs(t, err, ErrNydusImageBinaryNotFound)
	})

	t.Run("whitespace only", func(t *testing.T) {
		p := &Packer{logger: logrus.New(), nydusImagePath: "   "}
		err := p.ensureNydusImagePath()
		require.ErrorIs(t, err, ErrNydusImageBinaryNotFound)
	})
}

func TestGetNewBlobsHashEdgeCases(t *testing.T) {
	dir := t.TempDir()
	artifact, err := NewArtifact(dir)
	require.NoError(t, err)
	p := &Packer{Artifact: artifact, logger: logrus.New()}
	outputJSON := p.outputJSONPath()

	t.Run("no new blobs", func(t *testing.T) {
		data, _ := json.Marshal(BlobManifest{Blobs: []string{"aaa"}})
		require.NoError(t, os.WriteFile(outputJSON, data, 0644))
		hash, err := p.getNewBlobsHash([]string{"aaa"})
		require.NoError(t, err)
		require.Empty(t, hash)
	})

	t.Run("first new blob", func(t *testing.T) {
		data, _ := json.Marshal(BlobManifest{Blobs: []string{"aaa", "bbb"}})
		require.NoError(t, os.WriteFile(outputJSON, data, 0644))
		hash, err := p.getNewBlobsHash([]string{"aaa"})
		require.NoError(t, err)
		require.Equal(t, "bbb", hash)
	})

	t.Run("file not found", func(t *testing.T) {
		p2 := &Packer{Artifact: Artifact{OutputDir: "/nonexistent"}, logger: logrus.New()}
		_, err := p2.getNewBlobsHash(nil)
		require.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		require.NoError(t, os.WriteFile(outputJSON, []byte("{invalid}"), 0644))
		_, err := p.getNewBlobsHash(nil)
		require.Error(t, err)
	})
}

func TestInitLogger(t *testing.T) {
	logger, err := initLogger(logrus.DebugLevel)
	require.NoError(t, err)
	require.NotNil(t, logger)
	require.Equal(t, logrus.DebugLevel, logger.Level)
}

func TestGetBlobsFromBootstrapEmpty(t *testing.T) {
	p := &Packer{logger: logrus.New()}
	blobs, err := p.getBlobsFromBootstrap("")
	require.NoError(t, err)
	require.Empty(t, blobs)
}

func TestGetBlobsFromBootstrapInvalidBinary(t *testing.T) {
	p := &Packer{
		logger:         logrus.New(),
		nydusImagePath: "/nonexistent/nydus-image",
	}
	_, err := p.getBlobsFromBootstrap("/some/nonexistent/bootstrap")
	require.Error(t, err)
}

func TestDumpBlobBackendConfigOpenError(t *testing.T) {
	p := &Packer{
		logger: logrus.New(),
		BackendConfig: &S3BackendConfig{
			BucketName: "test",
		},
	}
	// Pass a path in a non-existent directory to trigger os.OpenFile error
	_, err := p.dumpBlobBackendConfig("/nonexistent/dir/config.json")
	require.Error(t, err)
}

func TestDumpBlobBackendConfigCleanupCalled(t *testing.T) {
	tmpDir := t.TempDir()
	p := &Packer{
		logger: logrus.New(),
		BackendConfig: &S3BackendConfig{
			Endpoint:        "s3.amazonaws.com",
			Scheme:          "https",
			AccessKeyID:     "ak",
			AccessKeySecret: "sk",
			Region:          "us-east-1",
			BucketName:      "bucket",
		},
	}
	filePath := filepath.Join(tmpDir, "config.json")
	cleanup, err := p.dumpBlobBackendConfig(filePath)
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	// File should exist before cleanup
	_, statErr := os.Stat(filePath)
	require.NoError(t, statErr)

	// Call the cleanup function — it should zero and remove the file
	cleanup()

	// File should be removed after cleanup
	_, statErr = os.Stat(filePath)
	require.True(t, os.IsNotExist(statErr))
}

func TestDumpBlobBackendConfigCleanupBadPath(t *testing.T) {
	tmpDir := t.TempDir()
	p := &Packer{
		logger:        logrus.New(),
		BackendConfig: &S3BackendConfig{BucketName: "b"},
	}
	filePath := filepath.Join(tmpDir, "cfg.json")
	cleanup, err := p.dumpBlobBackendConfig(filePath)
	require.NoError(t, err)

	// Remove the file before calling cleanup to trigger the open error path
	require.NoError(t, os.Remove(filePath))
	// Should not panic even though the file is missing
	cleanup()
}
