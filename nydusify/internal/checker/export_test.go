/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
)

func TestExportImage(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, img *nydusfs.Image, dest string)
		expect func(t *testing.T, dest string, err error)
	}{
		{
			name:  "export nydus index, manifest, config and bootstrap",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for _, path := range []string{"index.json", "manifest.json", "config.json", "bootstrap/image/image.boot"} {
					data, err := os.ReadFile(filepath.Join(dest, path))
					assert.NoError(err)
					assert.NotEmpty(data)
				}
			},
		},
		{
			name: "export oci manifest without index",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Kind = nydusfs.KindOCI
				img.Root = img.Desc
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				config, err := os.ReadFile(filepath.Join(dest, "config.json"))
				assert.NoError(err)
				assert.JSONEq(`{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin"],"Cmd":["sh"]},"rootfs":{"type":"","diff_ids":null}}`, string(config))
				assert.FileExists(filepath.Join(dest, "manifest.json"))
				assert.NoFileExists(filepath.Join(dest, "index.json"))
				assert.NoDirExists(filepath.Join(dest, "bootstrap"))
			},
		},
		{
			name: "reject nydus image without bootstrap",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Bootstrap = nil
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "nydus image is missing its bootstrap layer")
			},
		},
		{
			name: "reject occupied export path",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				if err := os.WriteFile(dest, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create export dir")
			},
		},
		{
			name: "report missing index",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Root.Digest = digest.FromString("absent index")
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write index.json")
			},
		},
		{
			name: "report missing manifest",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Desc.Digest = digest.FromString("absent manifest")
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write manifest.json")
			},
		},
		{
			name: "report unwritable manifest file",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Kind = nydusfs.KindOCI
				img.Root = img.Desc
				if err := os.MkdirAll(filepath.Join(dest, "manifest.json"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write manifest.json: write")
			},
		},
		{
			name: "report missing config",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Manifest.Config.Digest = digest.FromString("absent config")
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write config.json")
			},
		},
		{
			name: "report missing bootstrap layer",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				img.Bootstrap.Digest = digest.FromString("absent bootstrap")
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "extract bootstrap layer")
			},
		},
		{
			name: "report unwritable bootstrap file",
			setup: func(t *testing.T, img *nydusfs.Image, dest string) {
				if err := os.MkdirAll(filepath.Join(dest, "bootstrap", "image", "image.boot"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "extract bootstrap layer")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cs, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			config, err := oci.WriteJSON(ctx, cs, mockImageConfig, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
			if err != nil {
				t.Fatal(err)
			}

			bootstrap, err := oci.WriteBootstrapLayer(ctx, cs, []byte("bootstrap"), nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			manifest := ocispec.Manifest{Config: *config, Layers: []ocispec.Descriptor{*bootstrap}}
			desc, err := oci.WriteJSON(ctx, cs, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
			if err != nil {
				t.Fatal(err)
			}

			index, err := oci.WriteJSON(ctx, cs, ocispec.Index{Manifests: []ocispec.Descriptor{*desc}}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
			if err != nil {
				t.Fatal(err)
			}

			img := &nydusfs.Image{Root: *index, Desc: *desc, Manifest: manifest, Kind: nydusfs.KindNydus, Bootstrap: bootstrap}
			dest := filepath.Join(t.TempDir(), "export")
			tc.setup(t, img, dest)

			tc.expect(t, dest, exportImage(ctx, cs, img, dest))
		})
	}
}

func TestExtractBootstrapTree(t *testing.T) {
	tests := []struct {
		name   string
		layer  func(t *testing.T) []byte
		setup  func(t *testing.T, dest string)
		expect func(t *testing.T, dest string, err error)
	}{
		{
			name: "extract nested entries and skip links",
			layer: func(t *testing.T) []byte {
				return mockTar(t, []mockTarEntry{
					{header: tar.Header{Name: "image/", Typeflag: tar.TypeDir, Mode: 0o755}},
					{header: tar.Header{Name: "image/image.boot", Typeflag: tar.TypeReg, Mode: 0o644}, data: "bootstrap"},
					{header: tar.Header{Name: "image/meta/layer.blob.meta", Typeflag: tar.TypeReg, Mode: 0o644}, data: "meta"},
					{header: tar.Header{Name: "image/link", Typeflag: tar.TypeSymlink, Linkname: "image.boot"}},
				})
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(dest, "image", "image.boot"))
				assert.NoError(err)
				assert.Equal("bootstrap", string(data))
				data, err = os.ReadFile(filepath.Join(dest, "image", "meta", "layer.blob.meta"))
				assert.NoError(err)
				assert.Equal("meta", string(data))
				_, err = os.Lstat(filepath.Join(dest, "image", "link"))
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "reject path traversal",
			layer: func(t *testing.T) []byte {
				return mockTar(t, []mockTarEntry{
					{header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}, data: "escape"},
				})
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `invalid tar entry path "../escape"`)
				assert.NoFileExists(filepath.Join(filepath.Dir(dest), "escape"))
			},
		},
		{
			name: "reject corrupt archive",
			layer: func(t *testing.T) []byte {
				return []byte("not a tar archive")
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read bootstrap tar")
			},
		},
		{
			name: "reject directory entry over file",
			layer: func(t *testing.T) []byte {
				return mockTar(t, []mockTarEntry{{header: tar.Header{Name: "image/", Typeflag: tar.TypeDir, Mode: 0o755}}})
			},
			setup: func(t *testing.T, dest string) {
				if err := os.MkdirAll(dest, 0o755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(dest, "image"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
			},
		},
		{
			name: "reject file entry under file",
			layer: func(t *testing.T) []byte {
				return mockTar(t, mockBootstrapEntries)
			},
			setup: func(t *testing.T, dest string) {
				if err := os.MkdirAll(dest, 0o755); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(dest, "image"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create parent dir")
			},
		},
		{
			name: "reject occupied destination",
			layer: func(t *testing.T) []byte {
				return mockTar(t, mockBootstrapEntries)
			},
			setup: func(t *testing.T, dest string) {
				if err := os.WriteFile(dest, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create bootstrap dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			desc := mockBlob(t, cs, ocispec.MediaTypeImageLayer, tc.layer(t))
			dest := filepath.Join(t.TempDir(), "bootstrap")
			if tc.setup != nil {
				tc.setup(t, dest)
			}

			tc.expect(t, dest, extractBootstrapTree(context.Background(), cs, desc, dest))
		})
	}
}

func TestSafeJoin(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		expect func(t *testing.T, target string, err error)
	}{
		{
			name:  "nested entry",
			entry: "image/image.boot",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/base/image/image.boot", target)
			},
		},
		{
			name:  "absolute entry stays inside base",
			entry: "/image/image.boot",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/base/image/image.boot", target)
			},
		},
		{
			name:  "dot dot prefixed name",
			entry: "..image",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/base/..image", target)
			},
		},
		{
			name:  "parent entry",
			entry: "..",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `invalid tar entry path ".."`)
				assert.Empty(target)
			},
		},
		{
			name:  "nested escaping entry",
			entry: "image/../../escape",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `invalid tar entry path "image/../../escape"`)
				assert.Empty(target)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := safeJoin("/base", tc.entry)
			tc.expect(t, target, err)
		})
	}
}
