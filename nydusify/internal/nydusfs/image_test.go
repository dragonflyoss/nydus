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
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestFsVersion(t *testing.T) {
	tests := []struct {
		name string
		img  *Image
		run  func(t *testing.T, version string, ok bool)
	}{
		{
			name: "nydus image with annotation",
			img: &Image{
				Kind: KindNydus,
				Bootstrap: &ocispec.Descriptor{Annotations: map[string]string{
					nydus.LayerAnnotationNydusFsVersion: nydus.NydusFsVersion,
				}},
			},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(nydus.NydusFsVersion, version)
			},
		},
		{
			name: "nydus image without annotation",
			img:  &Image{Kind: KindNydus, Bootstrap: &ocispec.Descriptor{}},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(nydus.NydusFsVersionUnknown, version)
			},
		},
		{
			name: "nydus image without bootstrap",
			img:  &Image{Kind: KindNydus},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(version)
			},
		},
		{
			name: "oci image",
			img:  &Image{Kind: KindOCI},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(version)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version, ok := tc.img.FsVersion()
			tc.run(t, version, ok)
		})
	}
}

var (
	mockConfigData = []byte(`{"architecture":"amd64","os":"linux"}`)

	mockConfigDesc = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromBytes(mockConfigData),
		Size:      int64(len(mockConfigData)),
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

func storeMockBlob(t *testing.T, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if !assert.NoError(t, content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc)) {
		t.FailNow()
	}
	return desc
}

func storeMockJSON(t *testing.T, cs content.Store, mediaType string, v any) ocispec.Descriptor {
	data, err := json.Marshal(v)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return storeMockBlob(t, cs, mediaType, data)
}

func storeMockManifest(t *testing.T, cs content.Store, layers ...ocispec.Descriptor) ocispec.Descriptor {
	storeMockBlob(t, cs, ocispec.MediaTypeImageConfig, mockConfigData)
	manifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: mockConfigDesc, Layers: layers}
	manifest.SchemaVersion = 2
	return storeMockJSON(t, cs, ocispec.MediaTypeImageManifest, manifest)
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

func TestParseImage(t *testing.T) {
	tests := []struct {
		name   string
		root   func(t *testing.T, cs content.Store) ocispec.Descriptor
		expect func(t *testing.T, root ocispec.Descriptor, img *Image, err error)
	}{
		{
			name: "oci image",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return storeMockManifest(t, cs, mockOCILayer)
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal("registry.test/image:v1", img.Ref)
				assert.Equal(KindOCI, img.Kind)
				assert.Nil(img.Bootstrap)
				assert.Equal(root, img.Root)
				assert.Equal(root, img.Desc)
				assert.Equal([]ocispec.Descriptor{mockOCILayer}, img.Manifest.Layers)
				assert.Equal("amd64", img.Config.Architecture)
			},
		},
		{
			name: "nydus image",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return storeMockManifest(t, cs, mockBlobLayer, mockBootstrapLayer)
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(KindNydus, img.Kind)
				assert.Equal(&mockBootstrapLayer, img.Bootstrap)
				version, ok := img.FsVersion()
				assert.True(ok)
				assert.Equal("6", version)
			},
		},
		{
			name: "index resolves platform manifest",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				manifest := storeMockManifest(t, cs, mockOCILayer)
				manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				index := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{manifest}}
				index.SchemaVersion = 2
				return storeMockJSON(t, cs, ocispec.MediaTypeImageIndex, index)
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(root, img.Root)
				assert.Equal(ocispec.MediaTypeImageManifest, img.Desc.MediaType)
				assert.NotEqual(root.Digest, img.Desc.Digest)
				assert.Equal(KindOCI, img.Kind)
			},
		},
		{
			name: "bootstrap before data blob",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return storeMockManifest(t, cs, mockBootstrapLayer, mockBlobLayer)
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid nydus image layers")
				assert.ErrorContains(err, "is not the last layer")
				assert.Nil(img)
			},
		},
		{
			name: "missing image config",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				manifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: mockConfigDesc}
				manifest.SchemaVersion = 2
				return storeMockJSON(t, cs, ocispec.MediaTypeImageManifest, manifest)
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read image config")
				assert.Nil(img)
			},
		},
		{
			name: "missing manifest",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing"), Size: 7}
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read manifest")
				assert.Nil(img)
			},
		},
		{
			name: "unsupported root media type",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockOCILayer
			},
			expect: func(t *testing.T, root ocispec.Descriptor, img *Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "select platform manifest")
				assert.Nil(img)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			root := tc.root(t, cs)
			img, err := parseImage(context.Background(), cs, "registry.test/image:v1", root, platforms.All)
			tc.expect(t, root, img, err)
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
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			img, err := LoadImage(context.Background(), provider, tc.ref, platforms.All, remote.PullOption{}, remote.Source)
			tc.expect(t, img, err)
		})
	}
}
