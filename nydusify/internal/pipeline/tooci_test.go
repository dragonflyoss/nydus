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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockOptimizedBlob = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    digest.FromString("optimized blob"),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBlob:          "true",
			nydus.LayerAnnotationNydusBlobOptimized: "true",
		},
	}
)

func mockBuiltBlob(t *testing.T, cs content.Store, opt nydus.PackOption, name string, data []byte) ocispec.Descriptor {
	t.Helper()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, name), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var blob bytes.Buffer
	opt.WorkDir = t.TempDir()
	if err := nydus.BuildBlob(context.Background(), &blob, source, opt); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, blob.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	desc, err := oci.IngestBlobFile(context.Background(), cs, path, "")
	if err != nil {
		t.Fatal(err)
	}

	return desc
}

func mockNydusImage(t *testing.T, cs content.Store, blob ocispec.Descriptor, config string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	bootstrap, err := oci.WriteBootstrapLayer(ctx, cs, mockBootstrapData, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	configDesc, err := oci.WriteJSON(ctx, cs, json.RawMessage(config), ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		t.Fatal(err)
	}

	desc, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    *configDesc,
		Layers:    []ocispec.Descriptor{blob, *bootstrap},
	}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func mockNydusPlatformManifest(t *testing.T, cs content.Store, builder, arch, compressor string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	layer := mockBuiltBlob(t, cs, nydus.PackOption{BuilderPath: builder, Compressor: compressor}, "arch", []byte(arch))
	bootstrap, err := oci.WriteBootstrapLayer(ctx, cs, []byte("bootstrap is not used by per-layer export"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	config, err := oci.WriteJSON(ctx, cs, ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: arch},
		Config:   ocispec.ImageConfig{Env: []string{"KEEP=value"}},
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layer.Digest, bootstrap.Digest}},
		History:  []ocispec.History{{CreatedBy: "base"}, {CreatedBy: "Nydus Converter"}, {CreatedBy: "ENV KEEP=value", EmptyLayer: true}},
	}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		Config:      *config,
		Layers:      []ocispec.Descriptor{layer, *bootstrap},
		Annotations: map[string]string{"org.example.manifest": arch},
	}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, map[string]string{
		"containerd.io/gc.ref.content.l.0": layer.Digest.String(),
		"containerd.io/gc.ref.content.l.1": bootstrap.Digest.String(),
		"custom":                           "keep",
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: arch, OSFeatures: []string{nydus.ManifestOSFeatureNydus, "keep-feature"}}
	manifest.Annotations = map[string]string{"org.example.descriptor": arch}

	return *manifest
}

func mockNydusPlatformIndex(t *testing.T, cs content.Store, builder string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	index := ocispec.Index{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   ocispec.MediaTypeImageIndex,
		Annotations: map[string]string{"org.example.index": "preserved"},
		Manifests: []ocispec.Descriptor{
			mockNydusPlatformManifest(t, cs, builder, "amd64", "zstd"),
			mockNydusPlatformManifest(t, cs, builder, "arm64", "erofs-lz4"),
		},
	}
	for _, mediaType := range []string{ocispec.MediaTypeImageLayerGzip, "application/vnd.in-toto+json"} {
		manifest, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{Layers: []ocispec.Descriptor{{MediaType: mediaType}}},
			ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}
		index.Manifests = append(index.Manifests, *manifest)
	}
	opaque, err := oci.WriteJSON(ctx, cs, map[string]string{"opaque": "keep"}, ocispec.Descriptor{MediaType: "application/example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	index.Manifests = append(index.Manifests, *opaque)

	labels := map[string]string{"custom": "index-label"}
	for i, manifest := range index.Manifests {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.m.%d", i)] = manifest.Digest.String()
	}
	desc, err := oci.WriteJSON(ctx, cs, index, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, labels)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func TestConvertToOCI(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	tests := []struct {
		name    string
		builder bool
		local   bool
		source  func(t *testing.T, cs content.Store) ocispec.Descriptor
		opt     ToOCIOption
		expect  func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "reject forward compressor",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockNydusImage(t, cs, mockBlob(t, cs, "blob"), "{}")
			},
			opt: ToOCIOption{Compressor: "zstd"},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unsupported OCI compressor "zstd"`)
				assert.Nil(desc)
			},
		},
		{
			name: "reject layer source",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockGzipLayer
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("unsupported source media type %q", ocispec.MediaTypeImageLayerGzip))
				assert.Nil(desc)
			},
		},
		{
			name: "reject missing manifest",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing manifest")}
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat content")
				assert.Nil(desc)
			},
		},
		{
			name: "reject invalid manifest",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockContent(t, cs, ocispec.MediaTypeImageManifest, []byte("{"))
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read manifest json")
				assert.Nil(desc)
			},
		},
		{
			name: "reject oci manifest",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockManifest(t, cs, mockGzipLayer)
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is neither a nydus blob nor a nydus bootstrap")
				assert.Nil(desc)
			},
		},
		{
			name: "reject manifest without bootstrap",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockManifest(t, cs, mockBlob(t, cs, "blob"))
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "source is not a nydus image")
				assert.Nil(desc)
			},
		},
		{
			name: "reject missing work directory",
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockNydusImage(t, cs, mockBlob(t, cs, "blob"), "{}")
			},
			opt: ToOCIOption{WorkDir: "/nonexistent/work"},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create blob file")
				assert.Nil(desc)
			},
		},
		{
			name:    "reject invalid image config",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockNydusImage(t, cs, mockBuiltBlob(t, cs, nydus.PackOption{BuilderPath: builder}, "file", []byte("nydus layer")), "[]")
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "rewrite image config")
				assert.Nil(desc)
			},
		},
		{
			name:    "omit absent history",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockNydusImage(t, cs, mockBuiltBlob(t, cs, nydus.PackOption{BuilderPath: builder}, "file", []byte("nydus layer")), `{"os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var manifest ocispec.Manifest
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &manifest))
				assert.Len(manifest.Layers, 1)
				var digests []digest.Digest
				for _, layer := range manifest.Layers {
					assert.Equal(ocispec.MediaTypeImageLayer, layer.MediaType)
					digests = append(digests, layer.Digest)
				}

				var config map[string]json.RawMessage
				assert.NoError(oci.ReadJSON(context.Background(), cs, manifest.Config, &config))
				assert.NotContains(config, "history")

				var rootFS ocispec.RootFS
				assert.NoError(json.Unmarshal(config["rootfs"], &rootFS))
				assert.Equal(digests, rootFS.DiffIDs)
			},
		},
		{
			name:    "convert multi platform index",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockNydusPlatformIndex(t, cs, builder)
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotEqual(source.Digest, desc.Digest)

				var original, converted ocispec.Index
				assert.NoError(oci.ReadJSON(context.Background(), cs, source, &original))
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &converted))
				assert.Len(converted.Manifests, len(original.Manifests))
				assert.Equal(original.Annotations, converted.Annotations)

				originalLabels := map[string]string{"custom": "index-label"}
				var originalPassthrough, nydusPlatforms []ocispec.Descriptor
				for i, manifest := range original.Manifests {
					originalLabels[fmt.Sprintf("containerd.io/gc.ref.content.m.%d", i)] = manifest.Digest.String()
					if manifest.Platform == nil || manifest.Platform.OS != "linux" {
						originalPassthrough = append(originalPassthrough, manifest)
						continue
					}
					nydusPlatforms = append(nydusPlatforms, manifest)
				}
				labels, err := oci.Labels(context.Background(), cs, source.Digest)
				assert.NoError(err)
				assert.Equal(originalLabels, labels)
				for _, manifest := range nydusPlatforms {
					assert.Equal([]string{nydus.ManifestOSFeatureNydus, "keep-feature"}, manifest.Platform.OSFeatures)
				}

				indexLabels, err := oci.Labels(context.Background(), cs, desc.Digest)
				assert.NoError(err)
				assert.Equal("index-label", indexLabels["custom"])

				var (
					passthrough   []ocispec.Descriptor
					architectures []string
				)
				for i, manifestDesc := range converted.Manifests {
					assert.Equal(manifestDesc.Digest.String(), indexLabels[fmt.Sprintf("containerd.io/gc.ref.content.m.%d", i)])
					if manifestDesc.Platform == nil || manifestDesc.Platform.OS != "linux" {
						passthrough = append(passthrough, manifestDesc)
						continue
					}

					arch := manifestDesc.Platform.Architecture
					architectures = append(architectures, arch)
					assert.Equal(&ocispec.Platform{OS: "linux", Architecture: arch, OSFeatures: []string{"keep-feature"}}, manifestDesc.Platform)
					assert.Equal(map[string]string{"org.example.descriptor": arch}, manifestDesc.Annotations)

					manifest, config := readManifest(t, cs, manifestDesc)
					assert.Equal(arch, manifest.Annotations["org.example.manifest"])
					assert.Len(manifest.Layers, 1)

					var diffIDs []digest.Digest
					expectedLabels := map[string]string{"custom": "keep", "containerd.io/gc.ref.content.config": manifest.Config.Digest.String()}
					for j, layer := range manifest.Layers {
						assert.Equal(ocispec.MediaTypeImageLayer, layer.MediaType)
						expectedLabels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", j)] = layer.Digest.String()

						data, err := content.ReadBlob(context.Background(), cs, layer)
						assert.NoError(err)
						diffIDs = append(diffIDs, digest.FromBytes(data))

						files := map[string]string{}
						tr := tar.NewReader(bytes.NewReader(data))
						for {
							hdr, err := tr.Next()
							if err != nil {
								assert.ErrorIs(err, io.EOF)
								break
							}

							payload, err := io.ReadAll(tr)
							assert.NoError(err)
							files[hdr.Name] = string(payload)
						}
						assert.Equal(arch, files["arch"])
					}
					assert.Equal(diffIDs, config.RootFS.DiffIDs)
					assert.Equal(arch, config.Architecture)
					assert.Equal([]string{"KEEP=value"}, config.Config.Env)
					assert.Equal([]ocispec.History{{CreatedBy: "base"}, {CreatedBy: "ENV KEEP=value", EmptyLayer: true}}, config.History)

					manifestLabels, err := oci.Labels(context.Background(), cs, manifestDesc.Digest)
					assert.NoError(err)
					assert.Equal(expectedLabels, manifestLabels)
				}
				assert.Equal([]string{"amd64", "arm64"}, architectures)
				assert.Equal(originalPassthrough, passthrough)
			},
		},
		{
			name:    "reject index with missing later platform",
			builder: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs,
					mockNydusPlatformManifest(t, cs, builder, "amd64", "zstd"),
					ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing second platform")},
				)
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "inspect manifest")
				assert.Nil(desc)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:  "reject missing index",
			local: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing index")}
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat content")
				assert.Nil(desc)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:  "reject invalid index",
			local: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockContent(t, cs, ocispec.MediaTypeImageIndex, []byte("{"))
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read index json")
				assert.Nil(desc)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:  "reject index with missing platform manifest",
			local: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing manifest")})
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "inspect manifest")
				assert.Nil(desc)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:  "reject index with invalid platform manifest",
			local: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockContent(t, cs, ocispec.MediaTypeImageManifest, []byte("{")))
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "inspect manifest")
				assert.Nil(desc)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:  "reject index with missing platform blob",
			local: true,
			source: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockManifest(t, cs,
					ocispec.Descriptor{
						MediaType:   nydus.MediaTypeNydusBlob,
						Digest:      digest.FromString("missing blob"),
						Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true"},
					},
					mockBootstrapLayer,
				))
			},
			expect: func(t *testing.T, cs content.Store, opt ToOCIOption, source ocispec.Descriptor, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert manifest")
				assert.Nil(desc)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.builder && builder == "" {
				t.Skip("set NYDUS_TEST_BUILDER to run reverse conversion tests")
			}
			cs := mockStore(t)
			if tc.local {
				cs = mockLocalStore(t)
			}
			opt := tc.opt
			opt.BuilderPath = builder
			opt.WorkDir = cmp.Or(opt.WorkDir, t.TempDir())
			opt.Compressor = cmp.Or(opt.Compressor, "oci-tar")
			source := tc.source(t, cs)
			desc, err := ConvertToOCI(context.Background(), cs, source, opt)

			tc.expect(t, cs, opt, source, desc, err)
		})
	}
}

func TestNydusDataLayers(t *testing.T) {
	tests := []struct {
		name   string
		layers []ocispec.Descriptor
		expect func(t *testing.T, blobs []ocispec.Descriptor, err error)
	}{
		{
			name:   "reject oci layer",
			layers: []ocispec.Descriptor{mockGzipLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is neither a nydus blob nor a nydus bootstrap")
				assert.Nil(blobs)
			},
		},
		{
			name:   "reject missing bootstrap",
			layers: []ocispec.Descriptor{mockBlobDesc},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "source is not a nydus image")
				assert.Nil(blobs)
			},
		},
		{
			name: "skip bootstrap and optimized blob in order",
			layers: []ocispec.Descriptor{
				mockBlobDesc,
				{MediaType: nydus.MediaTypeNydusBlob, Digest: mockOtherBlobDigest},
				mockOptimizedBlob,
				mockBootstrapLayer,
			},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc, {MediaType: nydus.MediaTypeNydusBlob, Digest: mockOtherBlobDigest}}, blobs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blobs, err := nydusDataLayers(tc.layers)
			tc.expect(t, blobs, err)
		})
	}
}

func TestUnpackLayers(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run parallel export failure tests")
	}
	procs := runtime.GOMAXPROCS(max(2, runtime.GOMAXPROCS(0)))
	defer runtime.GOMAXPROCS(procs)

	tests := []struct {
		name   string
		cancel bool
		expect func(t *testing.T, ctx context.Context, blobs []ocispec.Descriptor, layers []unpackedLayer, err error)
	}{
		{
			name: "fail with the initiating layer error when one export fails",
			expect: func(t *testing.T, ctx context.Context, blobs []ocispec.Descriptor, layers []unpackedLayer, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unpack nydus layer "+blobs[0].Digest.String())
				assert.ErrorContains(err, "injected export failure")
				assert.NoError(ctx.Err())
				assert.Nil(layers)
			},
		},
		{
			name:   "fail when context is canceled during export",
			cancel: true,
			expect: func(t *testing.T, ctx context.Context, blobs []ocispec.Descriptor, layers []unpackedLayer, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unpack nydus layer")
				assert.Nil(layers)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cs := mockStore(t)
			var blobs []ocispec.Descriptor
			for _, name := range mockLayerNames {
				source := mockContent(t, cs, ocispec.MediaTypeImageLayer, mockTar(t, name, []byte(name+" layer payload")))
				desc, err := convertLayer(ctx, cs, source, nydus.PackOption{BuilderPath: builder, WorkDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				blobs = append(blobs, *desc)
			}

			var before []digest.Digest
			if err := cs.Walk(ctx, func(info content.Info) error {
				before = append(before, info.Digest)
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			exporter := filepath.Join(t.TempDir(), "exporter")
			if err := os.WriteFile(exporter, fmt.Appendf(nil, "#!/bin/sh\nexec %q -test.run=^TestExportChild$ -- \"$@\"\n", executable), 0o700); err != nil {
				t.Fatal(err)
			}
			scratch, control := t.TempDir(), t.TempDir()
			t.Setenv("NYDUS_EXPORT_CONTROL", control)
			t.Setenv("NYDUS_EXPORT_FAIL", blobs[0].Digest.Encoded())

			var (
				layers    []unpackedLayer
				unpackErr error
			)
			done := make(chan struct{})
			go func() {
				defer close(done)
				layers, unpackErr = unpackLayers(ctx, cs, blobs, ToOCIOption{BuilderPath: exporter, WorkDir: scratch, Compressor: "oci-tar"})
			}()

			var pids []int
			t.Cleanup(func() {
				cancel()
				for _, pid := range pids {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
				<-done
			})
			deadline := time.Now().Add(5 * time.Second)
			for _, blob := range blobs {
				pid := 0
				for pid == 0 && time.Now().Before(deadline) {
					data, _ := os.ReadFile(filepath.Join(control, blob.Digest.Encoded()))
					pid, _ = strconv.Atoi(string(data))
					if pid == 0 {
						time.Sleep(10 * time.Millisecond)
					}
				}
				if pid == 0 {
					t.Fatal("export peers did not both start and stream output")
				}
				pids = append(pids, pid)
			}

			if tc.cancel {
				cancel()
			} else if err := os.WriteFile(filepath.Join(control, "release"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("export failed to cancel and reap peers within 5s")
			}

			for _, pid := range pids {
				assert.ErrorIs(t, unix.Kill(pid, 0), unix.ESRCH)
			}
			scratchEntries, err := os.ReadDir(scratch)
			assert.NoError(t, err)
			assert.Empty(t, scratchEntries)
			var after []digest.Digest
			assert.NoError(t, cs.Walk(context.Background(), func(info content.Info) error {
				after = append(after, info.Digest)
				return nil
			}))
			assert.ElementsMatch(t, before, after)

			tc.expect(t, ctx, blobs, layers, unpackErr)
		})
	}
}

func TestRewriteOCIConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        json.RawMessage
		droppedLayers int
		expect        func(t *testing.T, config, rewritten json.RawMessage, err error)
	}{
		{
			name: "replace diff ids and drop history of removed layers but keep empty layer history",
			config: json.RawMessage(`{
				"architecture": "amd64",
				"os": "linux",
				"config": {
					"Env": ["PATH=/usr/bin"],
					"Cmd": []
				},
				"rootfs": {
					"type": "layers",
					"diff_ids": ["sha256:1114b6f54a6fbd8e0cb80e9d9ee92d86cf5bd06c1424375c3cdde4acce16d6fc"]
				},
				"history": [
					{"created_by": "RUN apt-get update"},
					{"created_by": "ENV PATH=/usr/bin", "empty_layer": true},
					{"created_by": "COPY app /app"},
					{"created_by": "Nydus Converter", "comment": "Nydus Bootstrap Layer"},
					{"created_by": "Nydus Optimizer", "comment": "Nydus Ondemand Blob Layer"}
				]
			}`),
			droppedLayers: 2,
			expect: func(t *testing.T, config, rewritten json.RawMessage, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var source, target map[string]json.RawMessage
				assert.NoError(json.Unmarshal(config, &source))
				assert.NoError(json.Unmarshal(rewritten, &target))
				var sourceConfig, targetConfig bytes.Buffer
				assert.NoError(json.Compact(&sourceConfig, source["config"]))
				assert.NoError(json.Compact(&targetConfig, target["config"]))
				assert.Equal(sourceConfig.String(), targetConfig.String())

				var rootFS ocispec.RootFS
				assert.NoError(json.Unmarshal(target["rootfs"], &rootFS))
				assert.Equal(ocispec.RootFS{Type: "layers", DiffIDs: mockDiffIDs}, rootFS)

				var history []ocispec.History
				assert.NoError(json.Unmarshal(target["history"], &history))
				assert.Equal([]ocispec.History{
					{CreatedBy: "RUN apt-get update"},
					{CreatedBy: "ENV PATH=/usr/bin", EmptyLayer: true},
					{CreatedBy: "COPY app /app"},
				}, history)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rewritten, err := rewriteOCIConfig(tc.config, mockDiffIDs, tc.droppedLayers)
			tc.expect(t, tc.config, rewritten, err)
		})
	}
}

func TestIsOCICompressor(t *testing.T) {
	tests := []struct {
		name       string
		compressor string
		expect     func(t *testing.T, ok bool)
	}{
		{
			name:       "accept oci gzip",
			compressor: "oci-gzip",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name:       "accept oci zstd",
			compressor: "oci-zstd",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name:       "accept oci tar",
			compressor: "oci-tar",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name: "reject empty compressor",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
		{
			name:       "reject forward zstd compressor",
			compressor: "zstd",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
		{
			name:       "reject forward none compressor",
			compressor: "none",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
		{
			name:       "reject gzip compressor",
			compressor: "gzip",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, IsOCICompressor(tc.compressor))
		})
	}
}

func TestParseCompressor(t *testing.T) {
	tests := []struct {
		name       string
		compressor string
		expect     func(t *testing.T, algo compression.Compression, err error)
	}{
		{
			name:       "parse oci gzip",
			compressor: "oci-gzip",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(compression.Gzip, algo)
			},
		},
		{
			name:       "parse oci zstd",
			compressor: "oci-zstd",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(compression.Zstd, algo)
			},
		},
		{
			name:       "parse oci tar",
			compressor: "oci-tar",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(compression.Uncompressed, algo)
			},
		},
		{
			name: "reject empty compressor",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unsupported OCI compressor ""`)
			},
		},
		{
			name:       "reject forward zstd compressor",
			compressor: "zstd",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unsupported OCI compressor "zstd"`)
			},
		},
		{
			name:       "reject forward none compressor",
			compressor: "none",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unsupported OCI compressor "none"`)
			},
		},
		{
			name:       "reject gzip compressor",
			compressor: "gzip",
			expect: func(t *testing.T, algo compression.Compression, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unsupported OCI compressor "gzip"`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			algo, err := parseCompressor(tc.compressor)
			tc.expect(t, algo, err)
		})
	}
}

func TestLayerMediaType(t *testing.T) {
	tests := []struct {
		name   string
		algo   compression.Compression
		expect func(t *testing.T, mediaType string)
	}{
		{
			name: "gzip layer",
			algo: compression.Gzip,
			expect: func(t *testing.T, mediaType string) {
				assert := assert.New(t)
				assert.Equal(ocispec.MediaTypeImageLayerGzip, mediaType)
			},
		},
		{
			name: "zstd layer",
			algo: compression.Zstd,
			expect: func(t *testing.T, mediaType string) {
				assert := assert.New(t)
				assert.Equal(ocispec.MediaTypeImageLayerZstd, mediaType)
			},
		},
		{
			name: "uncompressed layer",
			algo: compression.Uncompressed,
			expect: func(t *testing.T, mediaType string) {
				assert := assert.New(t)
				assert.Equal(ocispec.MediaTypeImageLayer, mediaType)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, layerMediaType(tc.algo))
		})
	}
}

func TestStripNydusOSFeature(t *testing.T) {
	tests := []struct {
		name     string
		platform *ocispec.Platform
		expect   func(t *testing.T, platform, stripped *ocispec.Platform)
	}{
		{
			name:     "strip nydus feature without mutating input",
			platform: &ocispec.Platform{OS: "linux", OSFeatures: []string{nydus.ManifestOSFeatureNydus, "other"}},
			expect: func(t *testing.T, platform, stripped *ocispec.Platform) {
				assert := assert.New(t)
				assert.Equal(&ocispec.Platform{OS: "linux", OSFeatures: []string{"other"}}, stripped)
				assert.Equal(&ocispec.Platform{OS: "linux", OSFeatures: []string{nydus.ManifestOSFeatureNydus, "other"}}, platform)
			},
		},
		{
			name: "keep nil platform",
			expect: func(t *testing.T, platform, stripped *ocispec.Platform) {
				assert := assert.New(t)
				assert.Nil(stripped)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.platform, stripNydusOSFeature(tc.platform))
		})
	}
}

func TestPruneLayerGCLabels(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(map[string]string{"containerd.io/gc.ref.content.confi": "keep"}, pruneLayerGCLabels(map[string]string{
		"containerd.io/gc.ref.content.l.0":   "sha256:a",
		"containerd.io/gc.ref.content.l.12":  "sha256:b",
		"containerd.io/gc.ref.content.confi": "keep",
	}))
}

func TestExportChild(t *testing.T) {
	control := os.Getenv("NYDUS_EXPORT_CONTROL")
	if control == "" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 || len(os.Args) <= separator+2 || os.Args[separator+1] != "export" {
		t.Fatalf("unexpected export arguments: %q", os.Args)
	}
	blob := os.Args[separator+2]
	data, err := os.ReadFile(blob)
	if err != nil || digest.FromBytes(data).Encoded() != filepath.Base(blob) {
		t.Fatalf("materialized blob %q: %v", blob, err)
	}
	if _, err := os.Stdout.Write(bytes.Repeat([]byte("partial tar stream"), 4096)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(control, filepath.Base(blob)), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if filepath.Base(blob) == os.Getenv("NYDUS_EXPORT_FAIL") {
			if _, err := os.Stat(filepath.Join(control, "release")); err == nil {
				_, _ = fmt.Fprintln(os.Stderr, "injected export failure")
				os.Exit(29)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}
