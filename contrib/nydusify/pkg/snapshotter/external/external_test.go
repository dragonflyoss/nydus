package external

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/stretchr/testify/assert"
)

// Mock implementation for backend.Handler
type mockHandler struct {
	backendFunc func(ctx context.Context) (*backend.Backend, error)
	handleFunc  func(ctx context.Context, file backend.File) ([]backend.Chunk, error)
}

func (m *mockHandler) Backend(ctx context.Context) (*backend.Backend, error) {
	return m.backendFunc(ctx)
}

func (m *mockHandler) Handle(ctx context.Context, file backend.File) ([]backend.Chunk, error) {
	return m.handleFunc(ctx, file)
}

// Mock implementation for backend.RemoteHandler
type mockRemoteHandler struct {
	handleFunc func(ctx context.Context) (*backend.Backend, []backend.FileAttribute, error)
}

func (m *mockRemoteHandler) Handle(ctx context.Context) (*backend.Backend, []backend.FileAttribute, error) {
	return m.handleFunc(ctx)
}

// TestHandle tests the Handle function.
func TestHandle(t *testing.T) {
	tmpDir := t.TempDir()
	metaOutput := filepath.Join(tmpDir, "meta.json")
	backendOutput := filepath.Join(tmpDir, "backend.json")
	attributesOutput := filepath.Join(tmpDir, "attributes.txt")

	mockHandler := &mockHandler{
		backendFunc: func(context.Context) (*backend.Backend, error) {
			return &backend.Backend{Version: "mock"}, nil
		},
		handleFunc: func(context.Context, backend.File) ([]backend.Chunk, error) {
			return []backend.Chunk{}, nil
		},
	}

	opts := Options{
		Dir:              tmpDir,
		MetaOutput:       metaOutput,
		BackendOutput:    backendOutput,
		AttributesOutput: attributesOutput,
		Handler:          mockHandler,
	}

	err := Handle(context.Background(), opts)
	assert.NoError(t, err)

	// Verify outputs
	assert.FileExists(t, metaOutput)
	assert.FileExists(t, backendOutput)
	assert.FileExists(t, attributesOutput)
}

// TestRemoteHandle tests the RemoteHandle function.
func TestRemoteHandle(t *testing.T) {
	tmpDir := t.TempDir()
	contextDir := filepath.Join(tmpDir, "context")
	backendOutput := filepath.Join(tmpDir, "backend.json")
	attributesOutput := filepath.Join(tmpDir, "attributes.txt")

	mockRemoteHandler := &mockRemoteHandler{
		handleFunc: func(context.Context) (*backend.Backend, []backend.FileAttribute, error) {
			return &backend.Backend{Version: "mock"},
				[]backend.FileAttribute{
					{
						RelativePath:           "testfile",
						Type:                   "regular",
						FileSize:               1024,
						BlobIndex:              0,
						BlobID:                 "blob1",
						ChunkSize:              "1MB",
						Chunk0CompressedOffset: 0,
						BlobSize:               "10MB",
						Mode:                   0644,
					},
				}, nil
		},
	}

	opts := Options{
		ContextDir:       contextDir,
		BackendOutput:    backendOutput,
		AttributesOutput: attributesOutput,
		RemoteHandler:    mockRemoteHandler,
	}

	err := RemoteHandle(context.Background(), opts)
	assert.NoError(t, err)

	// Verify outputs
	assert.FileExists(t, backendOutput)
	assert.FileExists(t, attributesOutput)
	assert.FileExists(t, filepath.Join(contextDir, "testfile"))
}

// TestBuildEmptyFiles tests the buildEmptyFiles function.
func TestBuildEmptyFiles(t *testing.T) {
	tmpDir := t.TempDir()

	fileAttrs := []backend.FileAttribute{
		{
			RelativePath: "dir1/file1",
			Mode:         0644,
		},
		{
			RelativePath: "dir2/file2",
			Mode:         0755,
		},
	}

	err := buildEmptyFiles(fileAttrs, tmpDir)
	assert.NoError(t, err)

	// Verify files are created
	assert.FileExists(t, filepath.Join(tmpDir, "dir1", "file1"))
	assert.FileExists(t, filepath.Join(tmpDir, "dir2", "file2"))

	// Verify file modes
	info, err := os.Stat(filepath.Join(tmpDir, "dir1", "file1"))
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode())

	info, err = os.Stat(filepath.Join(tmpDir, "dir2", "file2"))
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode())
}

func TestBuildAttr(t *testing.T) {
	ret := Result{
		Files: []backend.FileAttribute{
			{
				RelativePath: "dir1/file1",
			},
		},
	}
	attrs := buildAttr(&ret)
	assert.Equal(t, len(attrs), 1)
}
