package modctl

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
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
	t.Logf("mainfest desc: %v", maniDesc)
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

func TestChomoe(t *testing.T) {
	mode := uint32(0640)
	assert.Equal(t, uint32(0640), mode)
	testFile := "test.txt"
	f, err := os.Stat(testFile)
	require.Nil(t, err)
	assert.Equal(t, mode, uint32(f.Mode()))
	t.Logf("fmode: %o, mode: %o", f.Mode(), mode)
}
