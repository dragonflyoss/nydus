/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package oci_test

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

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

var (
	mockAMD64Platform = ocispec.Platform{OS: "linux", Architecture: "amd64"}

	mockARM64Platform = ocispec.Platform{OS: "linux", Architecture: "arm64"}

	mockAMD64Manifest = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("amd64 manifest"),
		Size:      14,
		Platform:  &mockAMD64Platform,
	}

	mockARM64Manifest = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("arm64 manifest"),
		Size:      14,
		Platform:  &mockARM64Platform,
	}

	mockPlatformlessManifest = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("platformless manifest"),
		Size:      21,
	}

	mockNestedIndex = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageIndex,
		Digest:    digest.FromString("nested index"),
		Size:      12,
		Platform:  &mockAMD64Platform,
	}
)

func mockLabeledStore(t *testing.T) content.Store {
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	return provider.ContentStore()
}

func mockBlob(t *testing.T, cs content.Store, mediaType string, data []byte, opts ...content.Opt) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if err := content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc, opts...); err != nil {
		t.Fatal(err)
	}

	return desc
}

func mockIndex(t *testing.T, cs content.Store, manifests ...ocispec.Descriptor) ocispec.Descriptor {
	index := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: manifests}
	index.SchemaVersion = 2
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}

	return mockBlob(t, cs, ocispec.MediaTypeImageIndex, data)
}

func TestResolveManifest(t *testing.T) {
	tests := []struct {
		name     string
		root     func(t *testing.T, cs content.Store) ocispec.Descriptor
		platform platforms.MatchComparer
		expect   func(t *testing.T, desc ocispec.Descriptor, err error)
	}{
		{
			name: "manifest root is returned as is",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockAMD64Manifest
			},
			platform: platforms.OnlyStrict(mockARM64Platform),
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockAMD64Manifest, desc)
			},
		},
		{
			name: "most specific platform wins",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockAMD64Manifest, mockARM64Manifest)
			},
			platform: platforms.Ordered(mockARM64Platform, mockAMD64Platform),
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockARM64Manifest.Digest, desc.Digest)
			},
		},
		{
			name: "manifest without platform matches",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockARM64Manifest, mockPlatformlessManifest)
			},
			platform: platforms.OnlyStrict(mockAMD64Platform),
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockPlatformlessManifest.Digest, desc.Digest)
			},
		},
		{
			name: "matching platform wins over a manifest without platform",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockPlatformlessManifest, mockAMD64Manifest)
			},
			platform: platforms.OnlyStrict(mockAMD64Platform),
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockAMD64Manifest.Digest, desc.Digest)
			},
		},
		{
			name: "non-manifest entries are skipped",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNestedIndex, mockARM64Manifest)
			},
			platform: platforms.OnlyStrict(mockAMD64Platform),
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "no manifest matches the requested platform")
				assert.Empty(desc)
			},
		},
		{
			name: "index without manifests",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs)
			},
			platform: platforms.All,
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "image index has no manifests")
			},
		},
		{
			name: "index missing from content store",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing"), Size: 7}
			},
			platform: platforms.All,
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read index")
			},
		},
		{
			name: "unsupported root media type",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("layer")}
			},
			platform: platforms.All,
			expect: func(t *testing.T, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `unsupported root media type "application/vnd.oci.image.layer.v1.tar+gzip"`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockLabeledStore(t)
			desc, err := oci.ResolveManifest(context.Background(), cs, tc.root(t, cs), tc.platform)

			tc.expect(t, desc, err)
		})
	}
}

func TestReadJSON(t *testing.T) {
	tests := []struct {
		name   string
		desc   func(t *testing.T, cs content.Store) ocispec.Descriptor
		expect func(t *testing.T, config ocispec.Image, err error)
	}{
		{
			name: "decodes stored json",
			desc: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockBlob(t, cs, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"arm64","os":"linux"}`))
			},
			expect: func(t *testing.T, config ocispec.Image, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockARM64Platform, config.Platform)
			},
		},
		{
			name: "invalid json",
			desc: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockBlob(t, cs, ocispec.MediaTypeImageConfig, []byte("not json"))
			},
			expect: func(t *testing.T, config ocispec.Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unmarshal "+digest.FromString("not json").String())
			},
		},
		{
			name: "missing blob",
			desc: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			},
			expect: func(t *testing.T, config ocispec.Image, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read blob "+digest.FromString("missing").String())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockLabeledStore(t)
			var config ocispec.Image
			err := oci.ReadJSON(context.Background(), cs, tc.desc(t, cs), &config)

			tc.expect(t, config, err)
		})
	}
}

func TestLabels(t *testing.T) {
	tests := []struct {
		name   string
		plain  bool
		dgst   func(t *testing.T, cs content.Store) digest.Digest
		expect func(t *testing.T, labels map[string]string, err error)
	}{
		{
			name: "content labels",
			dgst: func(t *testing.T, cs content.Store) digest.Digest {
				return mockBlob(t, cs, ocispec.MediaTypeImageLayer, []byte("labeled"), content.WithLabels(map[string]string{"key": "value"})).Digest
			},
			expect: func(t *testing.T, labels map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]string{"key": "value"}, labels)
			},
		},
		{
			name:  "store without label support",
			plain: true,
			dgst: func(t *testing.T, cs content.Store) digest.Digest {
				return mockBlob(t, cs, ocispec.MediaTypeImageLayer, []byte("unlabeled")).Digest
			},
			expect: func(t *testing.T, labels map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotNil(labels)
				assert.Empty(labels)
			},
		},
		{
			name: "missing content",
			dgst: func(t *testing.T, cs content.Store) digest.Digest {
				return digest.FromString("missing")
			},
			expect: func(t *testing.T, labels map[string]string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat content "+digest.FromString("missing").String())
				assert.Nil(labels)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockLabeledStore(t)
			if tc.plain {
				store, err := local.NewStore(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}

				cs = store
			}

			labels, err := oci.Labels(context.Background(), cs, tc.dgst(t, cs))

			tc.expect(t, labels, err)
		})
	}
}
