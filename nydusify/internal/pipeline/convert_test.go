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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
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

	errMockStore = errors.New("injected content store failure")
)

type mockContentStore struct {
	content.Store
	failAt int
	calls  []string
}

func (s *mockContentStore) call(operation string) error {
	s.calls = append(s.calls, operation)
	if len(s.calls) == s.failAt {
		return errMockStore
	}

	return nil
}

func (s *mockContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if err := s.call("read"); err != nil {
		return nil, err
	}

	return s.Store.ReaderAt(ctx, desc)
}

func (s *mockContentStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	if err := s.call("info"); err != nil {
		return content.Info{}, err
	}

	return s.Store.Info(ctx, dgst)
}

func (s *mockContentStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	if err := s.call("write"); err != nil {
		return nil, err
	}

	return s.Store.Writer(ctx, opts...)
}

func (s *mockContentStore) Update(ctx context.Context, info content.Info, fields ...string) (content.Info, error) {
	if err := s.call("update"); err != nil {
		return content.Info{}, err
	}

	return s.Store.Update(ctx, info, fields...)
}

func mockStore(t *testing.T) content.Store {
	t.Helper()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	return provider.ContentStore()
}

func mockLocalStore(t *testing.T) content.Store {
	t.Helper()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	return cs
}

func mockFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockBuilder(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nydus")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockTar(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func mockGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func mockContent(t *testing.T, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if err := content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
		t.Fatal(err)
	}

	return desc
}

func mockImage(t *testing.T, cs content.Store, imagePlatforms ...ocispec.Platform) ocispec.Descriptor {
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
			layer := mockTar(t, name, []byte(name+" layer for "+platform.Architecture))
			layers = append(layers, mockContent(t, cs, ocispec.MediaTypeImageLayerGzip, mockGzip(t, layer)))
			diffIDs = append(diffIDs, digest.FromBytes(layer))
			history = append(history, ocispec.History{CreatedBy: "ADD " + name})
		}

		config, err := oci.WriteJSON(ctx, cs, ocispec.Image{
			Platform: platform,
			Config:   mockImageConfig,
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
			History:  history,
		}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
		if err != nil {
			t.Fatal(err)
		}

		manifest, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    *config,
			Layers:    layers,
		}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Platform = &platform
		index.Manifests = append(index.Manifests, *manifest)
	}

	desc, err := oci.WriteJSON(ctx, cs, index, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func mockManifest(t *testing.T, cs content.Store, layers ...ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	diffIDs := make([]digest.Digest, 0, len(layers))
	for _, layer := range layers {
		diffIDs = append(diffIDs, digest.Digest(cmp.Or(layer.Annotations[nydus.LayerAnnotationUncompressed], layer.Digest.String())))
	}
	config, err := oci.WriteJSON(ctx, cs, ocispec.Image{Platform: mockPlatform, Config: mockImageConfig, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs}},
		ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		t.Fatal(err)
	}

	desc, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    *config,
		Layers:    layers,
	}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func mockBlob(t *testing.T, cs content.Store, data string, annotations ...string) ocispec.Descriptor {
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
	if err := content.WriteBlob(context.Background(), cs, dgst.String(), bytes.NewReader([]byte(data)), desc); err != nil {
		t.Fatal(err)
	}

	return desc
}

func mockBootstrap(t *testing.T, cs content.Store) ocispec.Descriptor {
	t.Helper()
	desc, err := oci.WriteBootstrapLayer(context.Background(), cs, mockBootstrapData, []nydus.BlobMetaFile{mockBlobMetaFile}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func mockNydusManifest(t *testing.T, cs content.Store) ocispec.Descriptor {
	t.Helper()
	return mockManifest(t, cs, mockBlob(t, cs, string(mockBlobData)), mockBootstrap(t, cs))
}

func mockIndex(t *testing.T, cs content.Store, manifests ...ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	desc, err := oci.WriteJSON(context.Background(), cs, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: manifests,
	}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func readManifest(t *testing.T, cs content.Store, desc ocispec.Descriptor) (ocispec.Manifest, ocispec.Image) {
	t.Helper()
	var (
		manifest ocispec.Manifest
		config   ocispec.Image
	)
	if err := oci.ReadJSON(context.Background(), cs, desc, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := oci.ReadJSON(context.Background(), cs, manifest.Config, &config); err != nil {
		t.Fatal(err)
	}

	return manifest, config
}

func readBootstrap(t *testing.T, cs content.Store, manifest ocispec.Manifest) map[string][]byte {
	t.Helper()
	_, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap == nil {
		t.Fatal("manifest has no nydus bootstrap layer")
	}

	entries := map[string][]byte{}
	if err := oci.WalkBootstrapLayer(context.Background(), cs, *bootstrap, func(hdr *tar.Header, tr *tar.Reader) error {
		data, err := io.ReadAll(tr)
		entries[hdr.Name] = data
		return err
	}); err != nil {
		t.Fatal(err)
	}

	return entries
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
			name:    "merge single platform index into nydus manifest",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockImage(t, cs, mockPlatform)
			},
			opt: Option{Annotations: mockManifestAnnotations},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(ocispec.MediaTypeImageManifest, desc.MediaType)
				assert.Equal(&mockPlatform, desc.Platform)

				manifest, config := readManifest(t, cs, *desc)
				blobs, _, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.Len(blobs, len(mockLayerNames))
				assert.ElementsMatch(blobs, converted)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)

				var diffIDs []digest.Digest
				for _, layer := range manifest.Layers {
					diffIDs = append(diffIDs, digest.Digest(layer.Annotations[nydus.LayerAnnotationUncompressed]))
				}
				assert.Equal(diffIDs, config.RootFS.DiffIDs)
				assert.Equal(mockImageConfig.Env, config.Config.Env)
				assert.Equal([]ocispec.History{{CreatedBy: "ADD lower"}, {CreatedBy: "ADD upper"}, mockBootstrapHistory}, config.History)

				labels, err := oci.Labels(context.Background(), cs, desc.Digest)
				assert.NoError(err)
				assert.Equal(manifest.Config.Digest.String(), labels["containerd.io/gc.ref.content.config"])
				for i, layer := range manifest.Layers {
					assert.Equal(layer.Digest.String(), labels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", i)])
				}
				assert.Contains(readBootstrap(t, cs, manifest), nydus.BootstrapFileNameInLayer)
			},
		},
		{
			name:    "keep multi platform index",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockImage(t, cs, mockPlatform, mockARM64Platform)
			},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(ocispec.MediaTypeImageIndex, desc.MediaType)
				assert.NotEqual(source.Digest, desc.Digest)
				assert.Len(converted, 2*len(mockLayerNames))

				var index ocispec.Index
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &index))

				var (
					manifestPlatforms []*ocispec.Platform
					architectures     []string
				)
				for _, manifestDesc := range index.Manifests {
					manifest, config := readManifest(t, cs, manifestDesc)
					blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
					assert.NoError(err)
					assert.NotNil(bootstrap)
					assert.Len(blobs, len(mockLayerNames))
					manifestPlatforms = append(manifestPlatforms, manifestDesc.Platform)
					architectures = append(architectures, config.Architecture)
				}
				assert.Equal([]*ocispec.Platform{&mockPlatform, &mockARM64Platform}, manifestPlatforms)
				assert.Equal([]string{mockPlatform.Architecture, mockARM64Platform.Architecture}, architectures)
			},
		},
		{
			name:    "select matching platform",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockImage(t, cs, mockPlatform, mockARM64Platform)
			},
			opt: Option{PlatformMC: platforms.Only(mockARM64Platform)},
			expect: func(t *testing.T, cs content.Store, source ocispec.Descriptor, desc *ocispec.Descriptor, converted []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(ocispec.MediaTypeImageManifest, desc.MediaType)
				assert.Equal(&mockARM64Platform, desc.Platform)
				assert.Len(converted, len(mockLayerNames))

				_, config := readManifest(t, cs, *desc)
				assert.Equal(mockARM64Platform.Architecture, config.Architecture)
			},
		},
		{
			name:    "return already converted source",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				desc, err := Convert(context.Background(), cs, mockImage(t, cs, mockPlatform), Option{BuilderPath: builder, WorkDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
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
			name: "reject missing source index",
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
			name: "reject missing source config",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				desc, err := oci.WriteJSON(context.Background(), cs, ocispec.Manifest{
					Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: digest.FromString("missing")},
				}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
				if err != nil {
					t.Fatal(err)
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
			name: "reject missing builder",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockImage(t, cs, mockPlatform)
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
			cs := mockStore(t)
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
