/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"os"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

var (
	mockPlatform = ocispec.Platform{OS: "linux", Architecture: "amd64"}

	mockARM64Platform = ocispec.Platform{OS: "linux", Architecture: "arm64"}

	mockManifestAnnotations = map[string]string{"org.example.image": "nydus"}

	mockImageConfig = ocispec.ImageConfig{Env: []string{"PATH=/usr/bin", "MOCK=value"}, Cmd: []string{"sh"}}

	mockLayerNames = []string{"lower", "upper"}

	mockBootstrapHistory = ocispec.History{CreatedBy: "Nydus Converter", Comment: "Nydus Bootstrap Layer"}

	mockGzipLayer = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("gzip layer"), Size: 10}

	mockBootstrapLayer = ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Digest:      digest.FromString("bootstrap layer"),
		Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
	}
)

func newMockStore(t *testing.T) content.Store {
	t.Helper()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return provider.ContentStore()
}

func writeMockImage(t *testing.T, cs content.Store, imagePlatforms ...ocispec.Platform) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex}
	for _, platform := range imagePlatforms {
		var (
			layers  []ocispec.Descriptor
			diffIDs []digest.Digest
			history []ocispec.History
		)
		for _, name := range mockLayerNames {
			var layer, compressed bytes.Buffer
			data := []byte(name + " layer for " + platform.Architecture)
			tw := tar.NewWriter(&layer)
			if !assert.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))})) {
				t.FailNow()
			}
			if _, err := tw.Write(data); !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.NoError(t, tw.Close()) {
				t.FailNow()
			}

			gw := gzip.NewWriter(&compressed)
			if _, err := gw.Write(layer.Bytes()); !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.NoError(t, gw.Close()) {
				t.FailNow()
			}

			desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromBytes(compressed.Bytes()), Size: int64(compressed.Len())}
			if !assert.NoError(t, content.WriteBlob(ctx, cs, desc.Digest.String(), bytes.NewReader(compressed.Bytes()), desc)) {
				t.FailNow()
			}
			layers = append(layers, desc)
			diffIDs = append(diffIDs, digest.FromBytes(layer.Bytes()))
			history = append(history, ocispec.History{CreatedBy: "ADD " + name})
		}

		config, err := oci.WriteJSON(ctx, cs, ocispec.Image{
			Platform: platform,
			Config:   mockImageConfig,
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
			History:  history,
		}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		manifest, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    *config,
			Layers:    layers,
		}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		manifest.Platform = &platform
		index.Manifests = append(index.Manifests, *manifest)
	}

	desc, err := oci.WriteJSON(ctx, cs, index, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return *desc
}

func writeMockManifest(t *testing.T, cs content.Store, layers ...ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	diffIDs := make([]digest.Digest, 0, len(layers))
	for _, layer := range layers {
		diffIDs = append(diffIDs, digest.Digest(cmp.Or(layer.Annotations[nydus.LayerAnnotationUncompressed], layer.Digest.String())))
	}
	config, err := oci.WriteJSON(ctx, cs, ocispec.Image{Platform: mockPlatform, Config: mockImageConfig, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs}},
		ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	desc, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    *config,
		Layers:    layers,
	}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return *desc
}

func writeMockBlob(t *testing.T, cs content.Store, data string, annotations ...string) ocispec.Descriptor {
	t.Helper()
	dgst := digest.FromString(data)
	desc := ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    dgst,
		Size:      int64(len(data)),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBlob:    "true",
			nydus.LayerAnnotationUncompressed: dgst.String(),
		},
	}
	for _, annotation := range annotations {
		desc.Annotations[annotation] = "true"
	}
	if !assert.NoError(t, content.WriteBlob(context.Background(), cs, dgst.String(), bytes.NewReader([]byte(data)), desc)) {
		t.FailNow()
	}

	return desc
}

func readMockManifest(t *testing.T, cs content.Store, desc ocispec.Descriptor) (ocispec.Manifest, ocispec.Image) {
	t.Helper()
	var (
		manifest ocispec.Manifest
		config   ocispec.Image
	)
	if !assert.NoError(t, oci.ReadJSON(context.Background(), cs, desc, &manifest)) {
		t.FailNow()
	}
	if !assert.NoError(t, oci.ReadJSON(context.Background(), cs, manifest.Config, &config)) {
		t.FailNow()
	}

	return manifest, config
}

func TestConvert(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	tests := []struct {
		name    string
		builder bool
		source  func(t *testing.T, cs content.Store) ocispec.Descriptor
		opt     Option
		expect  func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error)
	}{
		{
			name:    "merges single platform index into nydus manifest",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return writeMockImage(t, cs, mockPlatform)
			},
			opt: Option{Annotations: mockManifestAnnotations},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(ocispec.MediaTypeImageManifest, desc.MediaType)
				assert.Equal(&mockPlatform, desc.Platform)

				manifest, config := readMockManifest(t, cs, *desc)
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				if !assert.NoError(err) || !assert.NotNil(bootstrap) {
					t.FailNow()
				}
				assert.Len(blobs, len(mockLayerNames))
				assert.ElementsMatch(blobs, converted)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)

				var diffIDs []digest.Digest
				for _, layer := range manifest.Layers {
					diffIDs = append(diffIDs, digest.Digest(layer.Annotations[nydus.LayerAnnotationUncompressed]))
				}
				assert.Equal(diffIDs, config.RootFS.DiffIDs)
				assert.Equal(mockImageConfig.Env, config.Config.Env)
				assert.Len(config.History, len(mockLayerNames)+1)
				assert.Equal(mockBootstrapHistory, config.History[len(config.History)-1])

				labels, err := oci.Labels(context.Background(), cs, desc.Digest)
				assert.NoError(err)
				assert.Equal(manifest.Config.Digest.String(), labels["containerd.io/gc.ref.content.config"])
				assert.Equal(bootstrap.Digest.String(), labels["containerd.io/gc.ref.content.l.2"])

				var entries []string
				assert.NoError(oci.WalkBootstrapLayer(context.Background(), cs, *bootstrap, func(hdr *tar.Header, _ *tar.Reader) error {
					entries = append(entries, hdr.Name)
					return nil
				}))
				assert.Contains(entries, nydus.BootstrapFileNameInLayer)
			},
		},
		{
			name:    "keeps multi platform index",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return writeMockImage(t, cs, mockPlatform, mockARM64Platform)
			},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(ocispec.MediaTypeImageIndex, desc.MediaType)
				assert.NotEqual(source.Digest, desc.Digest)
				assert.Len(converted, 2*len(mockLayerNames))

				var index ocispec.Index
				if !assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &index)) || !assert.Len(index.Manifests, 2) {
					t.FailNow()
				}
				for i, platform := range []ocispec.Platform{mockPlatform, mockARM64Platform} {
					assert.Equal(&platform, index.Manifests[i].Platform)
					manifest, config := readMockManifest(t, cs, index.Manifests[i])
					blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
					assert.NoError(err)
					assert.NotNil(bootstrap)
					assert.Len(blobs, len(mockLayerNames))
					assert.Equal(platform.Architecture, config.Architecture)
				}
			},
		},
		{
			name:    "selects matching platform",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return writeMockImage(t, cs, mockPlatform, mockARM64Platform)
			},
			opt: Option{PlatformMC: platforms.Only(mockARM64Platform)},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(ocispec.MediaTypeImageManifest, desc.MediaType)
				assert.Equal(&mockARM64Platform, desc.Platform)
				assert.Len(converted, len(mockLayerNames))

				_, config := readMockManifest(t, cs, *desc)
				assert.Equal(mockARM64Platform.Architecture, config.Architecture)
			},
		},
		{
			name:    "returns already converted source",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				desc, err := Convert(context.Background(), cs, writeMockImage(t, cs, mockPlatform), Option{BuilderPath: builder, WorkDir: t.TempDir()})
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				return *desc
			},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&source, desc)
				assert.Empty(converted)
			},
		},
		{
			name: "rejects missing source index",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing")}
			},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "label nydus blob diff ids")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects missing source config",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				desc, err := oci.WriteJSON(context.Background(), cs, ocispec.Manifest{
					Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: digest.FromString("missing")},
				}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				return *desc
			},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "label source layer diff ids")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects missing builder",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return writeMockImage(t, cs, mockPlatform)
			},
			opt: Option{BuilderPath: "/nonexistent/nydus"},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert image")
				assert.ErrorContains(err, "convert layer")
				assert.Nil(desc)
				assert.Empty(converted)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.builder && builder == "" {
				t.Skip("set NYDUS_TEST_BUILDER to run real builder conversion tests")
			}
			cs := newMockStore(t)
			var (
				mu        sync.Mutex
				converted []ocispec.Descriptor
			)
			opt := tc.opt
			opt.BuilderPath = cmp.Or(opt.BuilderPath, builder)
			opt.WorkDir = t.TempDir()
			opt.OnBlobConverted = func(desc ocispec.Descriptor) {
				mu.Lock()
				defer mu.Unlock()
				converted = append(converted, desc)
			}
			source := tc.source(t, cs)
			desc, err := Convert(context.Background(), cs, source, opt)
			tc.expect(t, cs, source, desc, converted, err)
		})
	}
}
