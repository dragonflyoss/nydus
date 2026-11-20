/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/cache"
)

func TestBootstrapLayer_Blobs(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		hostDir bool
		prepare func(t *testing.T, fsDir string)
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
			files: []string{bootstrapFile, mockBlobID + cache.BlobMetaSuffix, mockOtherBlobID + cache.BlobMetaSuffix},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{mockBlobID, mockOtherBlobID}, blobs)
			},
		},
		{
			name:  "skip names that are no blob id",
			files: []string{"aaaa" + cache.BlobMetaSuffix, "..%2f" + mockBlobID + cache.BlobMetaSuffix, strings.ToUpper(mockBlobID) + cache.BlobMetaSuffix},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name: "missing image dir",
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(blobs)
			},
		},
		{
			name: "image dir that links to itself",
			prepare: func(t *testing.T, fsDir string) {
				assert.NoError(t, os.Symlink("image", filepath.Join(fsDir, "image")))
			},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve image dir")
				assert.Empty(blobs)
			},
		},
		{
			name: "skip a directory named as a blob meta",
			prepare: func(t *testing.T, fsDir string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(fsDir, "image", mockBlobID+cache.BlobMetaSuffix), 0o755))
			},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name: "more blob metas than a bootstrap can reference",
			prepare: func(t *testing.T, fsDir string) {
				assert.NoError(t, os.Mkdir(filepath.Join(fsDir, "image"), 0o755))
				for i := range maxBlobs + 1 {
					f, err := os.Create(filepath.Join(fsDir, "image", fmt.Sprintf("%064x", i)+cache.BlobMetaSuffix))
					if !assert.NoError(t, err) {
						return
					}
					assert.NoError(t, f.Close())
				}
			},
			expect: func(t *testing.T, blobs []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.Empty(blobs)
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

			if tc.prepare != nil {
				tc.prepare(t, fsDir)
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
		prepare     func(t *testing.T, src, dst string)
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
		{
			name: "stale bootstrap that cannot be removed",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(dst, "child"), 0o755))
			},
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove "+dst)
				assert.DirExists(dst)
			},
		},
		{
			name: "image dir that links to itself",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.RemoveAll(filepath.Dir(src)))
				assert.NoError(t, os.Symlink("image", filepath.Dir(src)))
			},
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve image dir")
				assert.NoFileExists(dst)
			},
		},
		{
			name: "layer without a bootstrap",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.Remove(src))
			},
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(dst)
			},
		},
		{
			name: "target dir that does not exist",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.Remove(filepath.Dir(dst)))
			},
			expect: func(t *testing.T, src, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "link "+src+" to "+dst)
				assert.NoFileExists(dst)
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

			src := filepath.Join(fsDir, "image", bootstrapFile)
			if tc.prepare != nil {
				tc.prepare(t, src, dst)
			}

			err := NewBootstrapLayer(fsDir).linkBootstrap(dst)
			tc.expect(t, src, dst, err)
		})
	}
}

func TestBootstrapLayer_seedCache(t *testing.T) {
	tests := []struct {
		name   string
		cached map[string]string
		blobs  []string
		expect func(t *testing.T, cacheDir string, err error)
	}{
		{
			name:  "seed blob metas",
			blobs: []string{"aaaa"},
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
			blobs:  []string{"aaaa"},
			expect: func(t *testing.T, cacheDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, _ := os.ReadFile(filepath.Join(cacheDir, "aaaa.blob.meta"))
				assert.Equal("cached", string(data))
			},
		},
		{
			name:  "blob meta the layer does not ship",
			blobs: []string{"aaaa", "bbbb"},
			expect: func(t *testing.T, cacheDir string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.FileExists(filepath.Join(cacheDir, "aaaa.blob.meta"))
				assert.NoFileExists(filepath.Join(cacheDir, "bbbb.blob.meta"))
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

			tc.expect(t, cacheDir, NewBootstrapLayer(fsDir).seedCache(cacheDir, tc.blobs))
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
		name    string
		prepare func(t *testing.T, src, dst string)
		expect  func(t *testing.T, dst string, err error)
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
		{
			name: "source that does not exist",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.Remove(src))
			},
			expect: func(t *testing.T, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open ")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(dst)
			},
		},
		{
			name: "target dir that does not exist",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.Remove(filepath.Dir(dst)))
			},
			expect: func(t *testing.T, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create temporary file for "+dst)
			},
		},
		{
			name: "source that cannot be read leaves no temporary file",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.Remove(src))
				assert.NoError(t, os.Mkdir(src, 0o755))
			},
			expect: func(t *testing.T, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "copy ")
				entries, err := os.ReadDir(filepath.Dir(dst))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "target that cannot be replaced leaves no temporary file",
			prepare: func(t *testing.T, src, dst string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(dst, "child"), 0o755))
			},
			expect: func(t *testing.T, dst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "rename ")
				entries, err := os.ReadDir(filepath.Dir(dst))
				assert.NoError(err)
				assert.Len(entries, 1)
				assert.DirExists(dst)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsDir := t.TempDir()
			writeLayer(t, fsDir, []string{bootstrapFile})
			src, dst := filepath.Join(fsDir, "image", bootstrapFile), filepath.Join(t.TempDir(), bootstrapFile)
			if tc.prepare != nil {
				tc.prepare(t, src, dst)
			}

			tc.expect(t, dst, NewBootstrapLayer(fsDir).copyFile(src, dst))
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
