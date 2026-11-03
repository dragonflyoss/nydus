/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestConvertMultiSource(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	tests := []struct {
		name    string
		builder bool
		sources func(t *testing.T, cs content.Store) []Source
		expect  func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error)
	}{
		{
			name:    "inherits config from upper image source",
			builder: true,
			sources: func(t *testing.T, cs content.Store) []Source {
				dir := t.TempDir()
				if !assert.NoError(t, os.WriteFile(filepath.Join(dir, "base"), []byte("directory source"), 0o644)) {
					t.FailNow()
				}

				image := writeMockImage(t, cs, mockPlatform)
				return []Source{{Dir: dir}, {Image: &image}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}

				manifest, config := readMockManifest(t, cs, *desc)
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.NotNil(bootstrap)
				assert.Len(blobs, 1+len(mockLayerNames))
				assert.Equal(mockManifestAnnotations, manifest.Annotations)
				assert.Equal(mockImageConfig.Env, config.Config.Env)
				assert.Len(config.RootFS.DiffIDs, len(manifest.Layers))
				if !assert.Len(config.History, len(manifest.Layers)) {
					t.FailNow()
				}
				assert.Equal(ocispec.History{CreatedBy: "Nydus Build", Comment: "Nydus Data Layer"}, config.History[0])
				assert.Equal(mockBootstrapHistory, config.History[len(config.History)-1])
			},
		},
		{
			name:    "reuses blobs of nydus image source",
			builder: true,
			sources: func(t *testing.T, cs content.Store) []Source {
				image, err := Convert(context.Background(), cs, writeMockImage(t, cs, mockPlatform), Option{BuilderPath: builder, WorkDir: t.TempDir()})
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				return []Source{{Image: image}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}

				source, _ := readMockManifest(t, cs, *sources[0].Image)
				sourceBlobs, _, _, err := nydus.SplitLayers(source.Layers)
				assert.NoError(err)
				manifest, config := readMockManifest(t, cs, *desc)
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.NotNil(bootstrap)
				assert.Equal(sourceBlobs, blobs)
				assert.Equal(mockImageConfig.Env, config.Config.Env)
			},
		},
		{
			name: "rejects missing image source",
			sources: func(t *testing.T, cs content.Store) []Source {
				return []Source{{Image: &ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing index")}}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert image source 0: label nydus blob diff ids")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects image source without matching platform",
			sources: func(t *testing.T, cs content.Store) []Source {
				image := writeMockImage(t, cs, mockARM64Platform)
				return []Source{{Image: &image}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "image index has no manifests")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects misplaced bootstrap layer",
			sources: func(t *testing.T, cs content.Store) []Source {
				bootstrap, err := oci.WriteBootstrapLayer(context.Background(), cs, []byte("bootstrap"), nil, nil)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				image := writeMockManifest(t, cs, *bootstrap, writeMockBlob(t, cs, "upper blob"))
				return []Source{{Image: &image}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported layer in image source")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects image source without layers",
			sources: func(t *testing.T, cs content.Store) []Source {
				image := writeMockManifest(t, cs)
				return []Source{{Image: &image}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "sources produced no nydus blob layers")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects invalid nydus blob",
			sources: func(t *testing.T, cs content.Store) []Source {
				image := writeMockManifest(t, cs, writeMockBlob(t, cs, "invalid blob"))
				return []Source{{Image: &image}}
			},
			expect: func(t *testing.T, cs content.Store, sources []Source, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stage blob")
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.builder && builder == "" {
				t.Skip("set NYDUS_TEST_BUILDER to run real builder conversion tests")
			}
			cs := newMockStore(t)
			sources := tc.sources(t, cs)
			desc, err := ConvertMultiSource(context.Background(), cs, MultiSourceOption{
				BuilderPath: builder,
				WorkDir:     t.TempDir(),
				Platform:    mockPlatform,
				Sources:     sources,
				Annotations: mockManifestAnnotations,
			})
			tc.expect(t, cs, sources, desc, err)
		})
	}
}
