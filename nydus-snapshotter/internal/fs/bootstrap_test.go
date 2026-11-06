/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestBootstrapLayer_Blobs(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		hostDir bool
		expect  func(t *testing.T, blobs []string, err error)
	}{
		{
			name:    "image dir linked to a host dir",
			hostDir: true,
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(blobs)
			},
		},
		{
			name:  "list blob metas",
			files: []string{bootstrapFile, mockBlobID + blobMetaSuffix, mockOtherBlobID + blobMetaSuffix},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{mockBlobID, mockOtherBlobID}, blobs)
			},
		},
		{
			name:  "skip names that are no blob id",
			files: []string{"aaaa" + blobMetaSuffix, "..%2f" + mockBlobID + blobMetaSuffix, strings.ToUpper(mockBlobID) + blobMetaSuffix},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name: "missing image dir",
			expect: func(t *testing.T, blobs []string, err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsDir := t.TempDir()
			writeLayer(t, fsDir, tc.files)
			if tc.hostDir {
				hostDir := t.TempDir()
				writeLayer(t, hostDir, []string{"host.blob.meta"})
				assert.NoError(t, os.Symlink(filepath.Join(hostDir, "image"), filepath.Join(fsDir, "image")))
			}

			blobs, err := NewBootstrapLayer(fsDir).Blobs()
			tc.expect(t, blobs, err)
		})
	}
}

func TestBootstrapLayer_linkBootstrap(t *testing.T) {
	tests := []struct {
		name        string
		existed     bool
		symlink     bool
		crossDevice bool
		expect      func(t *testing.T, src, dst string, err error)
	}{
		{
			name:        "copy the bootstrap across file systems",
			crossDevice: true,
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(dst)
				assert.NoError(err)
				assert.Equal(bootstrapFile, string(data))
				srcInfo, _ := os.Stat(src)
				dstInfo, _ := os.Stat(dst)
				assert.False(os.SameFile(srcInfo, dstInfo))
			},
		},
		{
			name:    "refuse a bootstrap linked to a host file",
			symlink: true,
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.NoFileExists(dst)
			},
		},
		{
			name: "link the bootstrap",
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				srcInfo, _ := os.Stat(src)
				dstInfo, _ := os.Stat(dst)
				assert.True(os.SameFile(srcInfo, dstInfo))
			},
		},
		{
			name:    "replace a stale bootstrap",
			existed: true,
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, _ := os.ReadFile(dst)
				assert.Equal(bootstrapFile, string(data))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsDir := t.TempDir()
			writeLayer(t, fsDir, []string{bootstrapFile})
			if tc.symlink {
				src := filepath.Join(fsDir, "image", bootstrapFile)
				assert.NoError(t, os.Remove(src))
				assert.NoError(t, os.Symlink("/etc/hostname", src))
			}

			dst := filepath.Join(t.TempDir(), bootstrapFile)
			if tc.crossDevice {
				dst = filepath.Join(crossDeviceDir(t, fsDir), bootstrapFile)
			}

			if tc.existed {
				assert.NoError(t, os.WriteFile(dst, []byte("stale"), 0o644))
			}

			err := NewBootstrapLayer(fsDir).linkBootstrap(dst)
			tc.expect(t, filepath.Join(fsDir, "image", bootstrapFile), dst, err)
		})
	}
}

func TestBootstrapLayer_seedCache(t *testing.T) {
	tests := []struct {
		name   string
		cached map[string]string
		expect func(t *testing.T, cacheDir string, err error)
	}{
		{
			name: "seed blob metas",
			expect: func(t *testing.T, cacheDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, _ := os.ReadFile(filepath.Join(cacheDir, "aaaa.blob.meta"))
				assert.Equal("aaaa.blob.meta", string(data))
			},
		},
		{
			name:   "keep a cached meta",
			cached: map[string]string{"aaaa.blob.meta": "cached"},
			expect: func(t *testing.T, cacheDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, _ := os.ReadFile(filepath.Join(cacheDir, "aaaa.blob.meta"))
				assert.Equal("cached", string(data))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsDir, cacheDir := t.TempDir(), t.TempDir()
			writeLayer(t, fsDir, []string{"aaaa.blob.meta"})
			for name, content := range tc.cached {
				assert.NoError(t, os.WriteFile(filepath.Join(cacheDir, name), []byte(content), 0o644))
			}

			tc.expect(t, cacheDir, NewBootstrapLayer(fsDir).seedCache(cacheDir, []string{"aaaa"}))
		})
	}
}

func writeLayer(t *testing.T, fsDir string, files []string) {
	t.Helper()
	for _, name := range files {
		assert.NoError(t, os.MkdirAll(filepath.Join(fsDir, "image"), 0o755))
		assert.NoError(t, os.WriteFile(filepath.Join(fsDir, "image", name), []byte(name), 0o644))
	}
}

func TestBootstrapLayer_copyFile(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, dst string, err error)
	}{
		{
			name: "copy through a temporary file",
			expect: func(t *testing.T, dst string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(dst)
				assert.NoError(err)
				assert.Equal(bootstrapFile, string(data))
				info, err := os.Stat(dst)
				assert.NoError(err)
				assert.Equal(os.FileMode(0o644), info.Mode())
				entries, err := os.ReadDir(filepath.Dir(dst))
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsDir := t.TempDir()
			writeLayer(t, fsDir, []string{bootstrapFile})
			dst := filepath.Join(t.TempDir(), bootstrapFile)
			tc.expect(t, dst, NewBootstrapLayer(fsDir).copyFile(filepath.Join(fsDir, "image", bootstrapFile), dst))
		})
	}
}

func crossDeviceDir(t *testing.T, dir string) string {
	t.Helper()
	shm, err := os.MkdirTemp("/dev/shm", "nydus-test-") //nolint:usetesting // another file system than t.TempDir
	if err != nil {
		t.Skipf("create a dir on /dev/shm: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })

	var a, b unix.Stat_t
	if unix.Stat(dir, &a) != nil || unix.Stat(shm, &b) != nil || a.Dev == b.Dev {
		t.Skip("/dev/shm is on the same file system")
	}

	return shm
}
