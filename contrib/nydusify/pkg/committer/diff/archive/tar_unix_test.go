//go:build !windows

package archive

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChmodTarEntry(t *testing.T) {
	// On Unix, chmodTarEntry returns the permission unchanged
	require.Equal(t, os.FileMode(0644), chmodTarEntry(0644))
	require.Equal(t, os.FileMode(0755), chmodTarEntry(0755))
	require.Equal(t, os.FileMode(0), chmodTarEntry(0))
	require.Equal(t, os.FileMode(0777), chmodTarEntry(0777))
}

func TestSetHeaderForSpecialDevice(t *testing.T) {
	tmpDir := t.TempDir()
	regularFile := filepath.Join(tmpDir, "regular.txt")
	os.WriteFile(regularFile, []byte("data"), 0644)

	fi, err := os.Stat(regularFile)
	require.NoError(t, err)

	hdr := &tar.Header{
		Name:     "regular.txt",
		Typeflag: tar.TypeReg,
	}
	err = setHeaderForSpecialDevice(hdr, regularFile, fi)
	require.NoError(t, err)
	// Regular files have no block/char device bits, so devmajor/devminor stay 0
	require.Equal(t, int64(0), hdr.Devmajor)
	require.Equal(t, int64(0), hdr.Devminor)
}

func TestOpen(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("content"), 0644)

	f, err := open(testFile)
	require.NoError(t, err)
	require.NotNil(t, f)
	f.Close()

	_, err = open(filepath.Join(tmpDir, "nonexistent"))
	require.Error(t, err)
}

func TestGetxattr(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("content"), 0644)

	// No xattr set - should return nil, nil
	val, err := getxattr(testFile, "user.test")
	require.NoError(t, err)
	require.Nil(t, val)

	// Nonexistent file
	_, err = getxattr(filepath.Join(tmpDir, "nonexistent"), "user.test")
	require.Error(t, err)
}
