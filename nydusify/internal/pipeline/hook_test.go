/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockDiffIDs = []digest.Digest{digest.FromString("lower diff"), digest.FromString("upper diff")}

	mockOverrideAnnotations = map[string]string{"org.example.existing": "override", "org.example.added": "value"}
)

func TestConvertHookFunc(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		descs       func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor)
		expect      func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "ignore unconverted layer",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				return mockGzipLayer, nil
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "return converted layer",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				blob := mockBlob(t, cs, "converted blob")
				return mockGzipLayer, &blob
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(newDesc, desc)
			},
		},
		{
			name: "collapse single manifest index",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				index := mockImage(t, cs, mockPlatform)
				return index, &index
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(ocispec.MediaTypeImageManifest, desc.MediaType)
				assert.Equal(&mockPlatform, desc.Platform)
			},
		},
		{
			name: "keep multi manifest index",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				index := mockImage(t, cs, mockPlatform, mockARM64Platform)
				return index, &index
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(newDesc, desc)
			},
		},
		{
			name: "reject unreadable index",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				index := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing index")}
				return index, &index
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read index json")
				assert.Nil(desc)
			},
		},
		{
			name:        "annotate unchanged nydus manifest and keep its platform",
			annotations: mockOverrideAnnotations,
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				desc, err := oci.WriteJSON(context.Background(), cs, ocispec.Manifest{
					MediaType:   ocispec.MediaTypeImageManifest,
					Layers:      []ocispec.Descriptor{mockBlobDesc, mockBootstrapLayer},
					Annotations: map[string]string{"org.example.existing": "keep"},
				}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
				if err != nil {
					t.Fatal(err)
				}
				desc.Platform = &mockPlatform

				return *desc, nil
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotEqual(orgDesc.Digest, desc.Digest)
				assert.Equal(orgDesc.Platform, desc.Platform)

				var manifest ocispec.Manifest
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &manifest))
				assert.Equal(mockOverrideAnnotations, manifest.Annotations)
			},
		},
		{
			name:        "skip annotating unchanged ordinary manifest",
			annotations: mockOverrideAnnotations,
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				return mockManifest(t, cs, mockGzipLayer), nil
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name:        "keep attestation manifest unannotated",
			annotations: mockManifestAnnotations,
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				manifest := mockManifest(t, cs, ocispec.Descriptor{MediaType: "application/vnd.in-toto+json", Digest: digest.FromString("attestation")})
				return manifest, &manifest
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(newDesc, desc)
			},
		},
		{
			name:        "reject unreadable manifest to annotate",
			annotations: mockManifestAnnotations,
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing manifest")}, nil
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read manifest json")
				assert.Nil(desc)
			},
		},
		{
			name: "reject merge of missing blob",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				manifest := mockManifest(t, cs, ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromString("missing blob")})
				return manifest, &manifest
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "merge nydus layers: open blob")
				assert.Nil(desc)
			},
		},
		{
			name: "reject merge of invalid blob",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				manifest := mockManifest(t, cs, mockBlob(t, cs, "invalid blob"))
				return manifest, &manifest
			},
			expect: func(t *testing.T, cs content.Store, orgDesc ocispec.Descriptor, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "merge nydus layers: stage blob")
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			orgDesc, newDesc := tc.descs(t, cs)
			desc, err := ConvertHookFunc(nydus.MergeOption{WorkDir: t.TempDir()}, tc.annotations)(context.Background(), cs, orgDesc, newDesc)

			tc.expect(t, cs, orgDesc, newDesc, desc, err)
		})
	}
}

func TestRewriteNydusManifestAnnotations(t *testing.T) {
	tests := []struct {
		name   string
		failAt int
		expect func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "annotate nydus manifest",
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				manifest, _ := readManifest(t, cs, *desc)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)
			},
		},
		{
			name:   "fail to read manifest",
			failAt: 1,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:   "fail to load manifest labels",
			failAt: 2,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:   "fail to open manifest writer",
			failAt: 3,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:   "fail to stat written manifest",
			failAt: 4,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			manifest := mockNydusManifest(t, cs)
			desc, err := rewriteNydusManifestAnnotations(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, manifest, mockManifestAnnotations)

			tc.expect(t, cs, manifest, desc, err)
		})
	}
}

func TestConvertIndex(t *testing.T) {
	tests := []struct {
		name   string
		failAt int
		expect func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "collapse single manifest index",
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&source, desc)
			},
		},
		{
			name:   "fail to read index",
			failAt: 1,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			manifest := mockNydusManifest(t, cs)
			index := mockIndex(t, cs, manifest)
			desc, err := convertIndex(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, &index)

			tc.expect(t, cs, manifest, desc, err)
		})
	}
}

func TestConvertManifest(t *testing.T) {
	tests := []struct {
		name   string
		failAt int
		expect func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "annotate merged nydus manifest",
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				manifest, _ := readManifest(t, cs, *desc)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)
			},
		},
		{
			name:   "fail to load manifest labels",
			failAt: 1,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:   "fail to read manifest",
			failAt: 2,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:   "fail to open manifest writer",
			failAt: 3,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:   "fail to stat written manifest",
			failAt: 4,
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			manifest := mockNydusManifest(t, cs)
			desc, err := convertManifest(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, &manifest, nydus.MergeOption{WorkDir: t.TempDir()}, mockManifestAnnotations)

			tc.expect(t, cs, manifest, desc, err)
		})
	}
}

func TestRewriteBootstrapConfig(t *testing.T) {
	tests := []struct {
		name   string
		config json.RawMessage
		expect func(t *testing.T, config, rewritten json.RawMessage, err error)
	}{
		{
			name: "replace diff ids and append history but keep empty runtime config fields",
			config: json.RawMessage(`{
				"architecture": "amd64",
				"os": "linux",
				"config": {
					"Env": ["PATH=/usr/bin"],
					"Entrypoint": ["/entrypoint.sh"],
					"Cmd": [],
					"WorkingDir": "/app",
					"ExposedPorts": {},
					"Labels": {"a": "b"}
				},
				"rootfs": {
					"type": "layers",
					"diff_ids": ["sha256:1114b6f54a6fbd8e0cb80e9d9ee92d86cf5bd06c1424375c3cdde4acce16d6fc"]
				},
				"history": [{"created_by": "base"}]
			}`),
			expect: func(t *testing.T, config, rewritten json.RawMessage, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var source, target ocispec.Image
				assert.NoError(json.Unmarshal(config, &source))
				assert.NoError(json.Unmarshal(rewritten, &target))
				source.RootFS.DiffIDs = mockDiffIDs
				source.History = append(source.History, mockBootstrapHistory)
				assert.Equal(source, target)
			},
		},
		{
			name: "keep unknown top level fields",
			config: json.RawMessage(`{
				"architecture": "arm64",
				"os": "linux",
				"variant": "v8",
				"config": {"Cmd": ["sh"]},
				"rootfs": {"type": "layers", "diff_ids": []},
				"custom_top_level": {"keep": "me"}
			}`),
			expect: func(t *testing.T, config, rewritten json.RawMessage, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var fields map[string]json.RawMessage
				assert.NoError(json.Unmarshal(rewritten, &fields))
				assert.Contains(fields, "custom_top_level")
				assert.Contains(fields, "variant")
			},
		},
		{
			name:   "reject invalid json",
			config: json.RawMessage(`{`),
			expect: func(t *testing.T, config, rewritten json.RawMessage, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unmarshal image config")
				assert.Nil(rewritten)
			},
		},
		{
			name:   "reject invalid rootfs",
			config: json.RawMessage(`{"rootfs":true}`),
			expect: func(t *testing.T, config, rewritten json.RawMessage, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unmarshal image config rootfs")
				assert.Nil(rewritten)
			},
		},
		{
			name:   "reject invalid history",
			config: json.RawMessage(`{"history":true}`),
			expect: func(t *testing.T, config, rewritten json.RawMessage, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unmarshal image config history")
				assert.Nil(rewritten)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rewritten, err := rewriteBootstrapConfig(tc.config, mockDiffIDs)
			tc.expect(t, tc.config, rewritten, err)
		})
	}
}
