/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockConfigData = []byte(`{"architecture":"amd64","os":"linux"}`)

	mockConfigDesc = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromBytes(mockConfigData),
		Size:      int64(len(mockConfigData)),
	}

	mockConfig = ocispec.Image{
		Platform: ocispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
	}

	mockOCILayer = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("oci layer"),
		Size:      9,
	}

	mockBlobLayer = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    digest.FromString("nydus blob"),
		Size:      10,
	}

	mockBootstrapLayer = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("nydus bootstrap"),
		Size:      15,
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBootstrap: "true",
			nydus.LayerAnnotationNydusFsVersion: "6",
		},
	}
)

func mockBlob(t *testing.T, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if err := content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
		t.Fatal(err)
	}

	return desc
}

func mockJSON(t *testing.T, cs content.Store, mediaType string, v any) ocispec.Descriptor {
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return mockBlob(t, cs, mediaType, data)
}

func mockManifest(t *testing.T, cs content.Store, layers ...ocispec.Descriptor) ocispec.Descriptor {
	mockBlob(t, cs, ocispec.MediaTypeImageConfig, mockConfigData)
	return mockJSON(t, cs, ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    mockConfigDesc,
		Layers:    layers,
	})
}

func TestImageKind_String(t *testing.T) {
	tests := []struct {
		name   string
		kind   ImageKind
		expect func(t *testing.T, s string)
	}{
		{
			name: "nydus image",
			kind: KindNydus,
			expect: func(t *testing.T, s string) {
				assert := assert.New(t)
				assert.Equal("nydus", s)
			},
		},
		{
			name: "oci image",
			kind: KindOCI,
			expect: func(t *testing.T, s string) {
				assert := assert.New(t)
				assert.Equal("oci", s)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.kind.String())
		})
	}
}

func TestImage_FsVersion(t *testing.T) {
	tests := []struct {
		name   string
		img    *Image
		expect func(t *testing.T, version string, ok bool)
	}{
		{
			name: "nydus image with annotation",
			img: &Image{
				Kind: KindNydus,
				Bootstrap: &ocispec.Descriptor{
					Annotations: map[string]string{
						nydus.LayerAnnotationNydusFsVersion: nydus.NydusFsVersion,
					},
				},
			},
			expect: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(nydus.NydusFsVersion, version)
			},
		},
		{
			name: "nydus image without annotation",
			img:  &Image{Kind: KindNydus, Bootstrap: &ocispec.Descriptor{}},
			expect: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(nydus.NydusFsVersionUnknown, version)
			},
		},
		{
			name: "nydus image without bootstrap",
			img:  &Image{Kind: KindNydus},
			expect: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(version)
			},
		},
		{
			name: "oci image",
			img:  &Image{Kind: KindOCI},
			expect: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(version)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version, ok := tc.img.FsVersion()

			tc.expect(t, version, ok)
		})
	}
}

func TestLoadImage(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		expect func(t *testing.T, img *Image, err error)
	}{
		{
			name: "invalid reference",
			ref:  "Registry.test/Image:v1",
			expect: func(t *testing.T, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `pull: parse reference "Registry.test/Image:v1"`)
				assert.Nil(img)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}

			img, err := LoadImage(context.Background(), provider, tc.ref, platforms.All, remote.PullOption{}, remote.Source)

			tc.expect(t, img, err)
		})
	}
}

func TestParseImage(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor)
		expect func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error)
	}{
		{
			name: "oci image",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				manifest := mockManifest(t, cs, mockOCILayer)
				return manifest, manifest
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Image{
					Ref:  "registry.test/image:v1",
					Root: root,
					Desc: root,
					Manifest: ocispec.Manifest{
						Versioned: specs.Versioned{SchemaVersion: 2},
						MediaType: ocispec.MediaTypeImageManifest,
						Config:    mockConfigDesc,
						Layers:    []ocispec.Descriptor{mockOCILayer},
					},
					Config: mockConfig,
					Kind:   KindOCI,
				}, img)
			},
		},
		{
			name: "nydus image",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				manifest := mockManifest(t, cs, mockBlobLayer, mockBootstrapLayer)
				return manifest, manifest
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Image{
					Ref:  "registry.test/image:v1",
					Root: root,
					Desc: root,
					Manifest: ocispec.Manifest{
						Versioned: specs.Versioned{SchemaVersion: 2},
						MediaType: ocispec.MediaTypeImageManifest,
						Config:    mockConfigDesc,
						Layers:    []ocispec.Descriptor{mockBlobLayer, mockBootstrapLayer},
					},
					Config:    mockConfig,
					Kind:      KindNydus,
					Bootstrap: &mockBootstrapLayer,
				}, img)
			},
		},
		{
			name: "index resolves platform manifest",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				manifest := mockManifest(t, cs, mockOCILayer)
				manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				return mockJSON(t, cs, ocispec.MediaTypeImageIndex, ocispec.Index{
					Versioned: specs.Versioned{SchemaVersion: 2},
					MediaType: ocispec.MediaTypeImageIndex,
					Manifests: []ocispec.Descriptor{manifest},
				}), manifest
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotEqual(root.Digest, manifest.Digest)
				assert.Equal(&Image{
					Ref:  "registry.test/image:v1",
					Root: root,
					Desc: manifest,
					Manifest: ocispec.Manifest{
						Versioned: specs.Versioned{SchemaVersion: 2},
						MediaType: ocispec.MediaTypeImageManifest,
						Config:    mockConfigDesc,
						Layers:    []ocispec.Descriptor{mockOCILayer},
					},
					Config: mockConfig,
					Kind:   KindOCI,
				}, img)
			},
		},
		{
			name: "bootstrap before data blob",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				manifest := mockManifest(t, cs, mockBootstrapLayer, mockBlobLayer)
				return manifest, manifest
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid nydus image layers")
				assert.ErrorContains(err, "is not the last layer")
				assert.Nil(img)
			},
		},
		{
			name: "missing image config",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				manifest := mockJSON(t, cs, ocispec.MediaTypeImageManifest, ocispec.Manifest{
					Versioned: specs.Versioned{SchemaVersion: 2},
					MediaType: ocispec.MediaTypeImageManifest,
					Config:    mockConfigDesc,
				})
				return manifest, manifest
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read image config")
				assert.Nil(img)
			},
		},
		{
			name: "missing manifest",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				manifest := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing"), Size: 7}
				return manifest, manifest
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read manifest")
				assert.Nil(img)
			},
		},
		{
			name: "unsupported root media type",
			mock: func(t *testing.T, cs content.Store) (ocispec.Descriptor, ocispec.Descriptor) {
				return mockOCILayer, ocispec.Descriptor{}
			},
			expect: func(t *testing.T, root, manifest ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "select platform manifest")
				assert.Nil(img)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			root, manifest := tc.mock(t, cs)
			img, err := parseImage(context.Background(), cs, "registry.test/image:v1", root, platforms.All)

			tc.expect(t, root, manifest, img, err)
		})
	}
}
