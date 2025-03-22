package backend

import (
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
		err := bfsWalk(filepath.Join(tmpDir, "dir", "subdir"), func(path string, info os.FileInfo) error {
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
		err := bfsWalk(filepath.Join(tmpDir, "dir"), func(path string, info os.FileInfo) error {
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
