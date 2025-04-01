package backend

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper function to create a temporary directory and files for testing
func setupTestDir(t *testing.T) (string, func()) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "bfsWalkTest")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Create test files and directories
	err = os.Mkdir(filepath.Join(tmpDir, "dir"), 0755)
	if err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "dir", "file1"), []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}
	err = os.Mkdir(filepath.Join(tmpDir, "dir", "subdir"), 0755)
	if err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "dir", "subdir", "file2"), []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Cleanup function to remove the temporary directory
	cleanup := func() {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			t.Fatalf("failed to cleanup temp dir: %v", err)
		}
	}

	return tmpDir, cleanup
}

// TestBfsWalk tests the bfsWalk function with various cases.
func TestBfsWalk(t *testing.T) {
	// Setup test directory
	tmpDir, cleanup := setupTestDir(t)
	defer cleanup()

	t.Run("Invalid path", func(t *testing.T) {
		err := bfsWalk(filepath.Join(tmpDir, "invalid_path"), func(string, os.FileInfo) error { return nil })
		assert.Error(t, err)
	})

	t.Run("Single file", func(t *testing.T) {
		called := false
		err := bfsWalk(filepath.Join(tmpDir, "dir", "subdir"), func(path string, _ os.FileInfo) error {
			called = true
			assert.Equal(t, filepath.Join(tmpDir, "dir", "subdir", "file2"), path)
			return nil
		})
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("Empty directory", func(t *testing.T) {
		emptyDir := filepath.Join(tmpDir, "empty_dir")
		err := os.Mkdir(emptyDir, 0755)
		if err != nil {
			t.Fatalf("failed to create empty_dir: %v", err)
		}

		called := false
		err = bfsWalk(emptyDir, func(string, os.FileInfo) error {
			called = true
			return nil
		})
		assert.NoError(t, err)
		assert.False(t, called)
	})

	t.Run("Directory with files and subdirectories", func(t *testing.T) {
		var paths []string
		err := bfsWalk(filepath.Join(tmpDir, "dir"), func(path string, _ os.FileInfo) error {
			paths = append(paths, path)
			return nil
		})
		assert.NoError(t, err)
		expectedPaths := []string{
			filepath.Join(tmpDir, "dir", "file1"),
			filepath.Join(tmpDir, "dir", "subdir", "file2"),
		}
		assert.Equal(t, expectedPaths, paths)
	})
}

type MockChunk struct {
	ID        uint32
	Content   interface{}
	Offset    uint64
	Path      string
	ChunkSize string
	Digest    string
	Size      string
}

func (m *MockChunk) ObjectID() uint32 {
	return m.ID
}
func (m *MockChunk) ObjectContent() interface{} {
	return m.Content
}

func (m *MockChunk) ObjectOffset() uint64 {
	return m.Offset
}
func (m *MockChunk) FilePath() string {
	return m.Path
}
func (m *MockChunk) LimitChunkSize() string {
	return m.ChunkSize
}
func (m *MockChunk) BlobDigest() string {
	return m.Digest
}
func (m *MockChunk) BlobSize() string {
	return m.Size
}

type MockHandler struct {
	BackendFunc func(context.Context) (*Backend, error)
	HandleFunc  func(context.Context, File) ([]Chunk, error)
}

func (m MockHandler) Backend(ctx context.Context) (*Backend, error) {
	if m.BackendFunc == nil {
		return &Backend{}, nil
	}
	return m.BackendFunc(ctx)
}

func (m MockHandler) Handle(ctx context.Context, file File) ([]Chunk, error) {
	if m.HandleFunc == nil {
		return []Chunk{
			&MockChunk{
				Path: "test1",
			},
			&MockChunk{
				Path: "test2",
			},
		}, nil
	}
	return m.HandleFunc(ctx, file)
}

func TestWalk(t *testing.T) {
	walker := &Walker{}
	handler := MockHandler{}
	root := "/tmp/nydusify"
	os.MkdirAll(root, 0755)
	defer os.RemoveAll(root)
	os.CreateTemp(root, "test")
	_, err := walker.Walk(context.Background(), root, handler)
	assert.NoError(t, err)
}
