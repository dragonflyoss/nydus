/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockNativeBlob = func() []byte {
		footer := make([]byte, nydus.NydusBlobFooterSize)
		copy(footer, nydus.NydusBlobFooterMagic)
		binary.LittleEndian.PutUint32(footer[12:16], 1<<1)
		return footer
	}()

	mockFuseFailure = "echo 'mock fuse failure' >&2\nexit 7\n"
)

func mockOCIImage(t *testing.T, cs content.Store, entries []mockTarEntry) *nydusfs.Image {
	layer := mockBlob(t, cs, ocispec.MediaTypeImageLayer, mockTar(t, entries))
	return &nydusfs.Image{Kind: nydusfs.KindOCI, Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{layer}}}
}

func TestEnsurePrivileged(t *testing.T) {
	tests := []struct {
		name   string
		root   bool
		expect func(t *testing.T, err error)
	}{
		{
			name: "allow root",
			root: true,
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "reject unprivileged user",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "filesystem rule requires root privileges")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if (os.Geteuid() == 0) != tc.root {
				t.Skip("effective user does not match the case")
			}

			tc.expect(t, ensurePrivileged())
		})
	}
}

func TestFilesystemRule_Validate(t *testing.T) {
	mockAbsentImage := &nydusfs.Image{Kind: nydusfs.KindOCI, Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
		{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromString("absent layer")},
	}}}

	tests := []struct {
		name   string
		root   bool
		images func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image)
		expect func(t *testing.T, workDir string, err error)
	}{
		{
			name: "skip without target",
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				return mockAbsentImage, nil
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "skip without source",
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				return nil, mockAbsentImage
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "pass identical oci images",
			root: true,
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				return mockOCIImage(t, cs, mockLayerEntries), mockOCIImage(t, cs, mockLayerEntries)
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "report content mismatch",
			root: true,
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				drift := slices.Clone(mockLayerEntries)
				drift[1].data = "drift\n"
				return mockOCIImage(t, cs, mockLayerEntries), mockOCIImage(t, cs, drift)
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `filesystem mismatch: path "etc/hostname": content mismatch`)
			},
		},
		{
			name: "report extra target entry",
			root: true,
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				extra := append(slices.Clone(mockLayerEntries), mockTarEntry{header: tar.Header{Name: "etc/extra", Typeflag: tar.TypeReg, Mode: 0o644}})
				return mockOCIImage(t, cs, mockLayerEntries), mockOCIImage(t, cs, extra)
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `filesystem mismatch: path "etc/extra" exists in target but not in source`)
			},
		},
		{
			name: "report missing source layer",
			root: true,
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				return mockAbsentImage, mockOCIImage(t, cs, mockLayerEntries)
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mount source image: apply oci image")
			},
		},
		{
			name: "report missing target layer and clean source",
			root: true,
			images: func(t *testing.T, cs content.Store) (*nydusfs.Image, *nydusfs.Image) {
				return mockOCIImage(t, cs, mockLayerEntries), mockAbsentImage
			},
			expect: func(t *testing.T, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mount target image: apply oci image")
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() != 0 {
				t.Skip("applying oci layers with ownership requires root")
			}

			rule, _ := mountRule(t, "")
			rule.source, rule.target = tc.images(t, rule.cs)
			tc.expect(t, rule.workDir, rule.Validate(context.Background()))
		})
	}
}

func TestFilesystemRule_fuseMount(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string)
		expect func(t *testing.T, root, dir string, err error)
	}{
		{
			name:  "serve chunk layers through registry config",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {},
			expect: func(t *testing.T, root, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mock fuse failure")
				args := mockBuilderArgs(t, root)
				assert.Equal("fuse", args[0])
				assert.Contains(args, "--config")
				assert.NotContains(args, "--blob-dir")
				config, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
				assert.NoError(err)
				assert.Contains(string(config), "addr: https://registry.invalid")
				assert.Contains(string(config), "repository: source")
			},
		},
		{
			name: "serve native layers from local blob dir",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				img.Manifest.Layers = []ocispec.Descriptor{mockBlob(t, rule.cs, nydus.MediaTypeNydusBlob, mockNativeBlob)}
			},
			expect: func(t *testing.T, root, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mock fuse failure")
				args := mockBuilderArgs(t, root)
				blobDir := slices.Index(args, "--blob-dir")
				if !assert.Positive(blobDir) {
					t.FailNow()
				}

				assert.Equal(filepath.Join(dir, "blobs"), args[blobDir+1])
				assert.Contains(args, filepath.Join(dir, "cache"))
				assert.NotContains(args, "--config")
				data, err := os.ReadFile(filepath.Join(dir, "blobs", digest.FromBytes(mockNativeBlob).Encoded()))
				assert.NoError(err)
				assert.Equal(mockNativeBlob, data)
			},
		},
		{
			name: "reject blob meta colliding with cache entry",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				boot, err := oci.WriteBootstrapLayer(context.Background(), rule.cs, []byte("bootstrap"),
					[]nydus.BlobMetaFile{{Name: "layer.blob.meta", Data: []byte("meta")}}, nil)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				img.Bootstrap = boot
				assert.NoError(t, os.MkdirAll(filepath.Join(dir, "cache", "layer.blob.meta"), 0o755))
			},
			expect: func(t *testing.T, root, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "link blob meta to cache")
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
		{
			name: "reject occupied blob dir",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				img.Manifest.Layers = []ocispec.Descriptor{mockBlob(t, rule.cs, nydus.MediaTypeNydusBlob, mockNativeBlob)}
				assert.NoError(t, os.WriteFile(filepath.Join(dir, "blobs"), nil, 0o600))
			},
			expect: func(t *testing.T, root, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "materialize blob layers")
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
		{
			name: "reject invalid image reference",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				img.Ref = "Invalid Reference"
			},
			expect: func(t *testing.T, root, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "generate storage config")
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			rule, img := mountRule(t, mockBuilder(t, root, mockFuseFailure))
			dir := filepath.Join(root, "fuse")
			if !assert.NoError(t, os.Mkdir(dir, 0o755)) {
				t.FailNow()
			}

			tc.setup(t, &rule, img, dir)
			mountpoint, unmount, err := rule.fuseMount(context.Background(), dir, remote.Source, img)
			assert.Empty(t, mountpoint)
			assert.Nil(t, unmount)
			tc.expect(t, root, dir, err)
		})
	}
}

func TestWaitForMount(t *testing.T) {
	tests := []struct {
		name       string
		mountpoint func(t *testing.T) string
		expect     func(t *testing.T, err error)
	}{
		{
			name: "return once mountpoint is a different device",
			mountpoint: func(t *testing.T) string {
				return "/proc"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "time out on plain directory",
			mountpoint: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not become ready within 0s")
			},
		},
		{
			name: "report missing mountpoint",
			mountpoint: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "absent")
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, waitForMount(context.Background(), tc.mountpoint(t), 0, make(chan struct{})))
		})
	}
}

func TestIsMounted(t *testing.T) {
	tests := []struct {
		name   string
		paths  func(t *testing.T) (string, string)
		expect func(t *testing.T, mounted bool, err error)
	}{
		{
			name: "same device",
			paths: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				return dir, filepath.Dir(dir)
			},
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(mounted)
			},
		},
		{
			name: "different device",
			paths: func(t *testing.T) (string, string) {
				return "/proc", "/"
			},
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(mounted)
			},
		},
		{
			name: "missing parent",
			paths: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				return dir, filepath.Join(dir, "absent")
			},
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.False(mounted)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mounted, err := isMounted(tc.paths(t))
			tc.expect(t, mounted, err)
		})
	}
}

func TestUnmountFuse(t *testing.T) {
	tests := []struct {
		name    string
		helpers map[string]string
		expect  func(t *testing.T, calls string, err error)
	}{
		{
			name:    "unmount with fusermount3",
			helpers: map[string]string{"fusermount3": "exit 0", "umount": "exit 0"},
			expect: func(t *testing.T, calls string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("fusermount3 -u /mnt/nydus\n", calls)
			},
		},
		{
			name:    "fall back to umount",
			helpers: map[string]string{"fusermount3": "exit 1", "umount": "exit 0"},
			expect: func(t *testing.T, calls string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("fusermount3 -u /mnt/nydus\numount /mnt/nydus\n", calls)
			},
		},
		{
			name:    "report last helper failure",
			helpers: map[string]string{"fusermount": "exit 1", "umount": "exit 2"},
			expect: func(t *testing.T, calls string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `unmount "/mnt/nydus": exit status 2`)
				assert.Equal("fusermount -u /mnt/nydus\numount /mnt/nydus\n", calls)
			},
		},
		{
			name: "report missing helpers",
			expect: func(t *testing.T, calls string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unmount "/mnt/nydus": exec: "umount": executable file not found`)
				assert.Empty(calls)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			for name, body := range tc.helpers {
				script := "#!/bin/sh\necho \"${0##*/} $*\" >> '" + log + "'\n" + body + "\n"
				if !assert.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700)) {
					t.FailNow()
				}
			}

			t.Setenv("PATH", dir)
			err := unmountFuse("/mnt/nydus")
			calls, _ := os.ReadFile(log)
			tc.expect(t, string(calls), err)
		})
	}
}
