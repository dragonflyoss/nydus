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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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

	mockAbsentImage = &nydusfs.Image{
		Kind: nydusfs.KindOCI,
		Manifest: ocispec.Manifest{
			Layers: []ocispec.Descriptor{{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromString("absent layer")}},
		},
	}
)

func mockOCIImage(t *testing.T, cs content.Store, entries []mockTarEntry) *nydusfs.Image {
	layer := mockBlob(t, cs, ocispec.MediaTypeImageLayer, mockTar(t, entries))
	return &nydusfs.Image{Kind: nydusfs.KindOCI, Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{layer}}}
}

func mockFilesystemRule(t *testing.T, builder string) (filesystemRule, *nydusfs.Image) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	bootstrap, err := oci.WriteBootstrapLayer(context.Background(), provider.ContentStore(), []byte("bootstrap"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	img := &nydusfs.Image{Ref: "registry.invalid/source:tag", Kind: nydusfs.KindNydus, Bootstrap: bootstrap}
	return filesystemRule{cs: provider.ContentStore(), provider: provider, builder: builder, workDir: t.TempDir()}, img
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

			rule, _ := mockFilesystemRule(t, "")
			rule.source, rule.target = tc.images(t, rule.cs)
			tc.expect(t, rule.workDir, rule.Validate(context.Background()))
		})
	}
}

func TestFilesystemRule_mount(t *testing.T) {
	tests := []struct {
		name    string
		builder string
		setup   func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc)
		expect  func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error)
	}{
		{
			name: "reject occupied scratch dir",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {
				rule.workDir = filepath.Join(rule.workDir, "file")
				if err := os.WriteFile(rule.workDir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create scratch dir")
				assert.Empty(root)
				assert.Nil(cleanup)
				paths, err := filepath.Glob(filepath.Join(workDir, "fs-source-*"))
				assert.NoError(err)
				assert.Empty(paths)
			},
		},
		{
			name: "reject nydus image without bootstrap",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {
				img.Bootstrap = nil
			},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing its bootstrap")
				assert.Empty(root)
				assert.Nil(cleanup)
				paths, err := filepath.Glob(filepath.Join(workDir, "fs-source-*"))
				assert.NoError(err)
				assert.Empty(paths)
			},
		},
		{
			name: "report missing bootstrap layer",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {
				img.Bootstrap.Digest = digest.FromString("absent bootstrap")
			},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "extract bootstrap")
				assert.Empty(root)
				assert.Nil(cleanup)
				paths, err := filepath.Glob(filepath.Join(workDir, "fs-source-*"))
				assert.NoError(err)
				assert.Empty(paths)
			},
		},
		{
			name: "report missing blob layer",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {
				img.Manifest.Layers = []ocispec.Descriptor{{
					MediaType:   nydus.MediaTypeNydusBlob,
					Digest:      digest.FromString("absent blob"),
					Size:        100,
					Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true"},
				}}
			},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "inspect blob layers")
				assert.Empty(root)
				assert.Nil(cleanup)
				paths, err := filepath.Glob(filepath.Join(workDir, "fs-source-*"))
				assert.NoError(err)
				assert.Empty(paths)
			},
		},
		{
			name: "report missing oci layer",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {
				img.Kind = nydusfs.KindOCI
				img.Manifest = mockAbsentImage.Manifest
			},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "apply oci image")
				assert.Empty(root)
				assert.Nil(cleanup)
				paths, err := filepath.Glob(filepath.Join(workDir, "fs-source-*"))
				assert.NoError(err)
				assert.Empty(paths)
			},
		},
		{
			name:  "report builder start failure",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "start nydus fuse")
				assert.Empty(root)
				assert.Nil(cleanup)
				assert.NoError(ctx.Err())
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "report builder exit before ready",
			builder: mockFuseFailure,
			setup:   func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mock fuse failure")
				assert.Empty(root)
				assert.Nil(cleanup)
				assert.NoError(ctx.Err())
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "reap builder on cancellation",
			builder: "echo $$ > \"$(dirname \"$0\")/pid\"\nexec sleep 30\n",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, cancel context.CancelFunc) {
				pidFile := filepath.Join(filepath.Dir(rule.builder), "pid")
				done := make(chan struct{})
				t.Cleanup(func() { <-done })
				go func() {
					defer close(done)
					assert.Eventually(t, func() bool {
						data, err := os.ReadFile(pidFile)
						return err == nil && strings.TrimSpace(string(data)) != ""
					}, 2*time.Second, 10*time.Millisecond)
					cancel()
				}()
			},
			expect: func(t *testing.T, ctx context.Context, builderDir, workDir, root string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Empty(root)
				assert.Nil(cleanup)

				data, err := os.ReadFile(filepath.Join(builderDir, "pid"))
				assert.NoError(err)
				pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
				assert.NoError(err)
				assert.ErrorIs(syscall.Kill(pid, 0), syscall.ESRCH)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builderDir := t.TempDir()
			rule, img := mockFilesystemRule(t, mockBuilder(t, builderDir, tc.builder))
			workDir := rule.workDir
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tc.setup(t, &rule, img, cancel)

			root, cleanup, err := rule.mount(ctx, "source", remote.Source, img)
			tc.expect(t, ctx, builderDir, workDir, root, cleanup, err)
		})
	}
}

func TestFilesystemRule_fuseMount(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string)
		expect func(t *testing.T, root, dir, mountpoint string, unmount func(), err error)
	}{
		{
			name:  "serve chunk layers through registry config",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {},
			expect: func(t *testing.T, root, dir, mountpoint string, unmount func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mock fuse failure")
				assert.Empty(mountpoint)
				assert.Nil(unmount)
				assert.Equal([]string{
					"fuse",
					"--bootstrap", filepath.Join(dir, "bootstrap", "image.boot"),
					"--mountpoint", filepath.Join(dir, "mnt"),
					"--log-level", "warn",
					"--log-dir", filepath.Join(dir, "log"),
					"--config", filepath.Join(dir, "config.yaml"),
				}, mockBuilderArgs(t, root))
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
			expect: func(t *testing.T, root, dir, mountpoint string, unmount func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "mock fuse failure")
				assert.Empty(mountpoint)
				assert.Nil(unmount)
				assert.Equal([]string{
					"fuse",
					"--bootstrap", filepath.Join(dir, "bootstrap", "image.boot"),
					"--mountpoint", filepath.Join(dir, "mnt"),
					"--log-level", "warn",
					"--log-dir", filepath.Join(dir, "log"),
					"--blob-dir", filepath.Join(dir, "blobs"),
					"--cache-dir", filepath.Join(dir, "cache"),
				}, mockBuilderArgs(t, root))
				data, err := os.ReadFile(filepath.Join(dir, "blobs", digest.FromBytes(mockNativeBlob).Encoded()))
				assert.NoError(err)
				assert.Equal(mockNativeBlob, data)
			},
		},
		{
			name: "reject occupied cache dir",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "cache"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, root, dir, mountpoint string, unmount func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
				assert.Empty(mountpoint)
				assert.Nil(unmount)
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
		{
			name: "reject blob meta colliding with cache entry",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				boot, err := oci.WriteBootstrapLayer(context.Background(), rule.cs, []byte("bootstrap"),
					[]nydus.BlobMetaFile{{Name: "layer.blob.meta", Data: []byte("meta")}}, nil)
				if err != nil {
					t.Fatal(err)
				}

				img.Bootstrap = boot
				if err := os.MkdirAll(filepath.Join(dir, "cache", "layer.blob.meta"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, root, dir, mountpoint string, unmount func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "link blob meta to cache")
				assert.Empty(mountpoint)
				assert.Nil(unmount)
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
		{
			name: "reject occupied blob dir",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				img.Manifest.Layers = []ocispec.Descriptor{mockBlob(t, rule.cs, nydus.MediaTypeNydusBlob, mockNativeBlob)}
				if err := os.WriteFile(filepath.Join(dir, "blobs"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, root, dir, mountpoint string, unmount func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "materialize blob layers")
				assert.Empty(mountpoint)
				assert.Nil(unmount)
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
		{
			name: "reject invalid image reference",
			setup: func(t *testing.T, rule *filesystemRule, img *nydusfs.Image, dir string) {
				img.Ref = "Invalid Reference"
			},
			expect: func(t *testing.T, root, dir, mountpoint string, unmount func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "generate storage config")
				assert.Empty(mountpoint)
				assert.Nil(unmount)
				assert.Nil(mockBuilderArgs(t, root))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			rule, img := mockFilesystemRule(t, mockBuilder(t, root, mockFuseFailure))
			dir := filepath.Join(root, "fuse")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			tc.setup(t, &rule, img, dir)

			mountpoint, unmount, err := rule.fuseMount(context.Background(), dir, remote.Source, img)
			tc.expect(t, root, dir, mountpoint, unmount, err)
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
				if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			t.Setenv("PATH", dir)
			err := unmountFuse("/mnt/nydus")
			calls, _ := os.ReadFile(log)
			tc.expect(t, string(calls), err)
		})
	}
}
