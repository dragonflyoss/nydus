package modctl

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Test cases for readBlob function
func TestReadImageRefBlob(t *testing.T) {
	ctx := context.Background()
	targeRef := os.Getenv("NYDUS_MODEL_IMAGE_REF")
	if targeRef == "" {
		t.Skip("NYDUS_MODEL_IMAGE_REF is not set, skip test")
	}
	remoter, err := pkgPvd.DefaultRemote(targeRef, true)
	require.Nil(t, err)
	// Pull manifest
	maniDesc, err := remoter.Resolve(ctx)
	require.Nil(t, err)
	t.Logf("manifest desc: %v", maniDesc)
	rc, err := remoter.Pull(ctx, *maniDesc, true)
	require.Nil(t, err)
	defer rc.Close()
	var buf bytes.Buffer
	io.Copy(&buf, rc)
	var manifest ocispec.Manifest
	err = json.Unmarshal(buf.Bytes(), &manifest)
	require.Nil(t, err)
	t.Logf("manifest: %v", manifest)

	for _, layer := range manifest.Layers {
		startTime := time.Now()
		rsc, err := remoter.ReadSeekCloser(context.Background(), layer, true)
		require.Nil(t, err)
		defer rsc.Close()
		rs, ok := rsc.(io.ReadSeeker)
		require.True(t, ok)
		files, err := readTarBlob(rs)
		require.Nil(t, err)
		require.NotEqual(t, 0, len(files))
		t.Logf("files: %v, elapesed: %v", files, time.Since(startTime))
	}

}

// MockReadSeeker is a mock implementation of io.ReadSeeker
type MockReadSeeker struct {
	mock.Mock
}

func (m *MockReadSeeker) Read(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockReadSeeker) Seek(offset int64, whence int) (int64, error) {
	args := m.Called(offset, whence)
	return args.Get(0).(int64), args.Error(1)
}

func TestReadTarBlob(t *testing.T) {
	t.Run("Normal case: valid tar file", func(t *testing.T) {
		// Create a valid tar file in memory
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		files := []struct {
			name string
			size int64
		}{
			{"file1.txt", 10},
			{"file2.txt", 20},
			{"file3.txt", 30},
		}
		for _, file := range files {
			header := &tar.Header{
				Name: file.name,
				Size: file.size,
			}
			if err := tw.WriteHeader(header); err != nil {
				t.Fatalf("Failed to write tar header: %v", err)
			}
			if _, err := tw.Write(make([]byte, file.size)); err != nil {
				t.Fatalf("Failed to write tar content: %v", err)
			}
		}
		tw.Close()

		reader := bytes.NewReader(buf.Bytes()) // Convert *bytes.Buffer to io.ReadSeeker
		result, err := readTarBlob(reader)

		assert.NoError(t, err)
		assert.Len(t, result, len(files))

		for i, file := range files {
			assert.Equal(t, file.name, result[i].name)
			// Since the file size is less than 512 bytes, it will be padded to 512 bytes in the tar body.
			assert.Equal(t, uint64((2*i+1)*512), result[i].offset)
			assert.Equal(t, uint64(file.size), result[i].size)
		}
	})

	t.Run("Empty tar file", func(t *testing.T) {
		// Create an empty tar file in memory
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		tw.Close()

		// Call the function
		reader := bytes.NewReader(buf.Bytes()) // Convert *bytes.Buffer to io.ReadSeeker
		result, err := readTarBlob(reader)

		// Validate the result
		assert.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("I/O error during read", func(t *testing.T) {
		// Create a mock ReadSeeker that returns an error on Read
		mockReader := new(MockReadSeeker)
		mockReader.On("Read", mock.Anything).Return(0, errors.New("mock read error"))
		mockReader.On("Seek", mock.Anything, mock.Anything).Return(int64(0), nil)

		// Call the function
		_, err := readTarBlob(mockReader)

		// Validate the error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read tar file failed")
	})
}

func TestReadRawBlob(t *testing.T) {
	layer := ocispec.Descriptor{
		MediaType: modelspec.MediaTypeModelDatasetRaw,
		Size:      100,
	}
	fm := modelspec.FileMetadata{
		Name: "test.raw",
		Mode: 0644,
		Size: 100,
	}
	b, err := json.Marshal(fm)
	require.NoError(t, err)
	layer.Annotations = map[string]string{
		filePathKey:                      "test.raw",
		modelspec.AnnotationFileMetadata: string(b),
	}
	files, err := readRawBlob(layer)
	assert.NoError(t, err)
	assert.Equal(t, []fileInfo{{
		name:   "test.raw",
		mode:   0644,
		size:   100,
		offset: 0,
	}}, files)
}

func TestValidateTar(t *testing.T) {
	t.Run("Normal case: valid tar file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "testvalid.tar")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		tw := tar.NewWriter(tmpfile)
		err = tw.WriteHeader(&tar.Header{
			Name: "testfile.txt",
			Mode: 0600,
			Size: 13,
		})
		require.NoError(t, err)
		_, err = tw.Write([]byte("hello, world\n"))
		require.NoError(t, err)
		err = tw.Close()
		require.NoError(t, err)
		tmpfile.Close()

		f, err := os.Open(tmpfile.Name())
		require.NoError(t, err)
		defer f.Close()

		valid, err := validateTarFile(f)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Normal case: invalid tar file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "testinvalid.tar")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		_, err = tmpfile.Write([]byte("invalid tar content"))
		require.NoError(t, err)
		tmpfile.Close()

		f, err := os.Open(tmpfile.Name())
		require.NoError(t, err)
		defer f.Close()

		valid, err := validateTarFile(f)
		assert.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Empty tar file", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "testempty.tar")
		require.NoError(t, err)
		os.Truncate(tmpfile.Name(), 0)
		tmpfile.Close()

		f, err := os.Open(tmpfile.Name())
		require.NoError(t, err)
		defer f.Close()

		valid, err := validateTarFile(f)
		assert.NoError(t, err)
		assert.True(t, valid)
	})
}

func TestGetOption(t *testing.T) {
	t.Run("Valid srcRef", func(t *testing.T) {
		srcRef := "host/namespace/image:tag"
		modCtlRoot := "/mock/root"
		weightChunkSize := uint64(64 * 1024 * 1024)

		opt, err := GetOption(srcRef, modCtlRoot, weightChunkSize)
		assert.NoError(t, err)
		assert.Equal(t, "host", opt.RegistryHost)
		assert.Equal(t, "namespace", opt.Namespace)
		assert.Equal(t, "image", opt.ImageName)
		assert.Equal(t, "tag", opt.Tag)
		assert.Equal(t, weightChunkSize, opt.WeightChunkSize)
	})

	t.Run("Invalid srcRef format", func(t *testing.T) {
		srcRef := "invalid-ref"
		modCtlRoot := "/mock/root"
		weightChunkSize := uint64(64 * 1024 * 1024)

		_, err := GetOption(srcRef, modCtlRoot, weightChunkSize)
		assert.Error(t, err)
	})
}

func TestHandle(t *testing.T) {
	handler := &Handler{
		root: "/tmp",
	}

	t.Run("File ignored", func(t *testing.T) {
		file := backend.File{RelativePath: "ignored-file/link"}
		chunks, err := handler.Handle(context.Background(), file)
		assert.NoError(t, err)
		assert.Nil(t, chunks)
	})

	handler.blobsMap = make(map[string]blobInfo)
	handler.blobsMap["test_digest"] = blobInfo{
		mediaType: modelspec.MediaTypeModelWeight,
	}
	t.Run("Open file failure", func(t *testing.T) {
		file := backend.File{RelativePath: "test/test_digest/nonexistent-file"}
		_, err := handler.Handle(context.Background(), file)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "open tar file failed")
	})

	t.Run("Normal tar file", func(t *testing.T) {
		os.MkdirAll("/tmp/test/test_digest/", 0755)
		testFile, err := os.CreateTemp("/tmp/test/test_digest/", "test_tar")
		assert.NoError(t, err)
		defer testFile.Close()
		defer os.RemoveAll(testFile.Name())
		tw := tar.NewWriter(testFile)
		header := &tar.Header{
			Name: "test.txt",
			Mode: 0644,
			Size: 4,
		}
		assert.NoError(t, tw.WriteHeader(header))
		_, err = tw.Write([]byte("test"))
		assert.NoError(t, err)
		tw.Close()
		testFilePath := strings.TrimPrefix(testFile.Name(), "/tmp/")
		file := backend.File{RelativePath: testFilePath}
		chunks, err := handler.Handle(context.Background(), file)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(chunks))
	})

	t.Run("Normal raw file", func(t *testing.T) {
		os.MkdirAll("/tmp/test/test_digest/", 0755)
		testFile, err := os.CreateTemp("/tmp/test/test_digest/", "test_raw")
		assert.NoError(t, err)
		defer testFile.Close()
		defer os.RemoveAll(testFile.Name())
		testFile.Write([]byte("test"))
		testFilePath := strings.TrimPrefix(testFile.Name(), "/tmp/")
		file := backend.File{RelativePath: testFilePath}
		chunks, err := handler.Handle(context.Background(), file)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(chunks))
	})

}

func TestModctlBackend(t *testing.T) {
	handler := &Handler{
		blobs: []backend.Blob{
			{
				Config: backend.BlobConfig{
					MediaType: "application/vnd.cnai.model.weight.v1.tar",
					Digest:    "sha256:mockdigest",
					Size:      "1024",
					ChunkSize: "64MiB",
				},
			},
		},
	}

	bkd, err := handler.Backend(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "v1", bkd.Version)
	assert.Equal(t, "registry", bkd.Backends[0].Type)
	assert.Len(t, bkd.Blobs, 1)
}

func TestConvertToBlobs(t *testing.T) {
	manifestWithColon := &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{
				Digest:    digest.Digest("sha256:abc123"),
				MediaType: modelspec.MediaTypeModelWeight,
				Size:      100,
			},
		},
	}
	actualBlobs1 := convertToBlobs(manifestWithColon)
	assert.Equal(t, 1, len(actualBlobs1))
	assert.Equal(t, modelspec.MediaTypeModelWeight, actualBlobs1[0].Config.MediaType)
	assert.Equal(t, "abc123", actualBlobs1[0].Config.Digest)

	manifestWithoutColon := &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{
				Digest:    digest.Digest("abc123"),
				MediaType: modelspec.MediaTypeModelDataset,
				Size:      100,
			},
		},
	}
	actualBlobs2 := convertToBlobs(manifestWithoutColon)
	assert.Equal(t, 1, len(actualBlobs2))
	assert.Equal(t, modelspec.MediaTypeModelDataset, actualBlobs2[0].Config.MediaType)
	assert.Equal(t, "abc123", actualBlobs2[0].Config.Digest)
}

func TestExtractManifest(t *testing.T) {
	handler := &Handler{
		root: "/tmp/test",
	}
	tagPath := fmt.Sprintf(ManifestPath, handler.tag)
	manifestPath := filepath.Join(handler.root, ReposPath, handler.registryHost, handler.namespace, handler.imageName, tagPath)
	dir := filepath.Dir(manifestPath)
	os.MkdirAll(dir, 0755)
	maniFile, err := os.Create(manifestPath)
	assert.NoError(t, err)
	_, err = maniFile.WriteString("sha256:abc1234")
	assert.NoError(t, err)
	maniFile.Close()
	defer os.RemoveAll(manifestPath)
	t.Logf("manifest path: %s", manifestPath)
	os.MkdirAll(filepath.Dir(manifestPath), 0755)
	// No file
	_, err = handler.extractManifest()
	assert.Error(t, err)

	var m = ocispec.Manifest{
		Config: ocispec.Descriptor{
			MediaType: modelspec.MediaTypeModelWeight,
			Digest:    "sha256:abc1234",
			Size:      10,
		},
	}
	data, err := json.Marshal(m)
	assert.NoError(t, err)
	blobDir := "/tmp/test/content.v1/docker/registry/v2/blobs/sha256/ab/abc1234/"
	os.MkdirAll(blobDir, 0755)
	blobPath := blobDir + "data"
	blobFile, err := os.Create(blobPath)
	assert.NoError(t, err)
	defer os.RemoveAll(blobPath)
	io.Copy(blobFile, bytes.NewReader(data))
	blobFile.Close()

	mani, err := handler.extractManifest()
	assert.NoError(t, err)
	assert.Equal(t, mani.Config.Digest.String(), "sha256:abc1234")
}

func TestSetBlobsMap(t *testing.T) {
	handler := &Handler{
		root:     "/tmp",
		blobs:    make([]backend.Blob, 0),
		blobsMap: map[string]blobInfo{},
	}
	handler.blobs = append(handler.blobs, backend.Blob{
		Config: backend.BlobConfig{
			Digest: "sha256:abc1234",
		},
	})
	handler.setBlobsMap()
	assert.Equal(t, handler.blobsMap["sha256:abc1234"].blobDigest, "sha256:abc1234")
}

func TestSetWeightChunkSize(t *testing.T) {
	setWeightChunkSize(0)
	expectedDefault := "64MiB"
	assert.Equal(t, expectedDefault, mediaTypeChunkSizeMap[modelspec.MediaTypeModelWeight], "Weight media type should be set to default value")
	assert.Equal(t, expectedDefault, mediaTypeChunkSizeMap[modelspec.MediaTypeModelDataset], "Dataset media type should be set to default value")

	chunkSize := uint64(16 * 1024 * 1024)
	setWeightChunkSize(chunkSize)
	expectedNonDefault := humanize.IBytes(chunkSize)
	expectedNonDefault = strings.ReplaceAll(expectedNonDefault, " ", "")

	assert.Equal(t, expectedNonDefault, mediaTypeChunkSizeMap[modelspec.MediaTypeModelWeight], "Weight media type should match the specified chunk size")
	assert.Equal(t, expectedNonDefault, mediaTypeChunkSizeMap[modelspec.MediaTypeModelDataset], "Dataset media type should match the specified chunk size")
}

func TestNewHandler(t *testing.T) {
	// handler := &Handler{}
	t.Run("Run extract manifest failed", func(t *testing.T) {
		_, err := NewHandler(Option{})
		assert.Error(t, err)
	})

	t.Run("Run Normal", func(t *testing.T) {
		initHandlerPatches := gomonkey.ApplyFunc(initHandler, func(*Handler) error {
			return nil
		})
		defer initHandlerPatches.Reset()
		handler, err := NewHandler(Option{})
		assert.NoError(t, err)
		assert.NotNil(t, handler)
	})
}

func TestInitHandler(t *testing.T) {
	t.Run("Run initHandler failed", func(t *testing.T) {
		handler := &Handler{}
		extractManifestPatches := gomonkey.ApplyPrivateMethod(handler, "extractManifest", func() (*ocispec.Manifest, error) {
			return &ocispec.Manifest{}, nil
		})
		defer extractManifestPatches.Reset()
		err := initHandler(handler)
		assert.NoError(t, err)
	})
}
