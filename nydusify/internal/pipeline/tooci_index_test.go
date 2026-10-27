/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestConvertToOCIIndex(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run multi-platform reverse conversion")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	store := provider.ContentStore()
	scratch := t.TempDir()
	writeJSON := func(value any, mediaType string, labels map[string]string) ocispec.Descriptor {
		desc, err := oci.WriteJSON(ctx, store, value, ocispec.Descriptor{MediaType: mediaType}, labels)
		require.NoError(t, err)
		return *desc
	}
	index := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex,
		Annotations: map[string]string{"org.example.index": "preserved"},
	}
	for i, arch := range []string{"amd64", "arm64"} {
		source := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(source, "arch"), []byte(arch), 0o644))
		var blob bytes.Buffer
		require.NoError(t, nydus.BuildBlob(ctx, &blob, source, nydus.PackOption{
			BuilderPath: builder, WorkDir: scratch, Compressor: []string{"zstd", "erofs-lz4"}[i],
		}))
		path := filepath.Join(t.TempDir(), "blob")
		require.NoError(t, os.WriteFile(path, blob.Bytes(), 0o600))
		layer, err := oci.IngestBlobFile(ctx, store, path, "")
		require.NoError(t, err)
		boot, err := oci.WriteBootstrapLayer(ctx, store, []byte("bootstrap is not used by per-layer export"), nil, nil)
		require.NoError(t, err)
		config := writeJSON(ocispec.Image{
			Platform: ocispec.Platform{OS: "linux", Architecture: arch},
			Config:   ocispec.ImageConfig{Env: []string{"KEEP=value"}},
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layer.Digest, boot.Digest}},
			History: []ocispec.History{
				{CreatedBy: "base"}, {CreatedBy: "Nydus Converter"}, {CreatedBy: "ENV KEEP=value", EmptyLayer: true},
			},
		}, ocispec.MediaTypeImageConfig, nil)
		manifest := writeJSON(ocispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2}, Config: config,
			Layers: []ocispec.Descriptor{layer, *boot}, Annotations: map[string]string{"org.example.manifest": arch},
		}, ocispec.MediaTypeImageManifest, map[string]string{
			"containerd.io/gc.ref.content.l.0": layer.Digest.String(),
			"containerd.io/gc.ref.content.l.1": boot.Digest.String(), "custom": "keep",
		})
		manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: arch,
			OSFeatures: []string{nydus.ManifestOSFeatureNydus, "keep-feature"}}
		manifest.Annotations = map[string]string{"org.example.descriptor": arch}
		index.Manifests = append(index.Manifests, manifest)
	}
	for _, mediaType := range []string{ocispec.MediaTypeImageLayerGzip, "application/vnd.in-toto+json"} {
		manifest := writeJSON(ocispec.Manifest{Layers: []ocispec.Descriptor{{MediaType: mediaType}}},
			ocispec.MediaTypeImageManifest, nil)
		manifest.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}
		index.Manifests = append(index.Manifests, manifest)
	}
	index.Manifests = append(index.Manifests, writeJSON(map[string]string{"opaque": "keep"}, "application/example", nil))
	labels := map[string]string{"custom": "index-label"}
	for i, manifest := range index.Manifests {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.m.%d", i)] = manifest.Digest.String()
	}
	source := writeJSON(index, ocispec.MediaTypeImageIndex, labels)
	got, err := ConvertToOCI(ctx, store, source, ToOCIOption{BuilderPath: builder, WorkDir: scratch, Compressor: "oci-tar"})
	require.NoError(t, err)
	require.NotEqual(t, source.Digest, got.Digest)
	var converted ocispec.Index
	require.NoError(t, oci.ReadJSON(ctx, store, *got, &converted))
	require.Len(t, converted.Manifests, len(index.Manifests))
	require.Equal(t, index.Annotations, converted.Annotations)
	indexLabels, err := oci.Labels(ctx, store, got.Digest)
	require.NoError(t, err)
	require.Equal(t, "index-label", indexLabels["custom"])
	for i, desc := range converted.Manifests {
		require.Equal(t, desc.Digest.String(), indexLabels[fmt.Sprintf("containerd.io/gc.ref.content.m.%d", i)])
		if i >= 2 {
			require.Equal(t, index.Manifests[i], desc, "ordinary and attestation entries must pass through unchanged")
			continue
		}
		arch := []string{"amd64", "arm64"}[i]
		require.Equal(t, &ocispec.Platform{OS: "linux", Architecture: arch, OSFeatures: []string{"keep-feature"}}, desc.Platform)
		require.Equal(t, index.Manifests[i].Annotations, desc.Annotations)
		var manifest ocispec.Manifest
		require.NoError(t, oci.ReadJSON(ctx, store, desc, &manifest))
		require.Equal(t, arch, manifest.Annotations["org.example.manifest"])
		require.Len(t, manifest.Layers, 1, "bootstrap must not survive reverse conversion")
		require.Equal(t, ocispec.MediaTypeImageLayer, manifest.Layers[0].MediaType)
		data, err := content.ReadBlob(ctx, store, manifest.Layers[0])
		require.NoError(t, err)
		reader := tar.NewReader(bytes.NewReader(data))
		found := false
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			if header.Name == "arch" {
				payload, err := io.ReadAll(reader)
				require.NoError(t, err)
				require.Equal(t, arch, string(payload), "platforms must not exchange layer contents")
				found = true
			}
		}
		require.True(t, found)
		var config ocispec.Image
		require.NoError(t, oci.ReadJSON(ctx, store, manifest.Config, &config))
		require.Equal(t, []digest.Digest{digest.FromBytes(data)}, config.RootFS.DiffIDs)
		require.Equal(t, arch, config.Architecture)
		require.Equal(t, []string{"KEEP=value"}, config.Config.Env)
		require.Equal(t, []ocispec.History{{CreatedBy: "base"}, {CreatedBy: "ENV KEEP=value", EmptyLayer: true}}, config.History)
		gotLabels, err := oci.Labels(ctx, store, desc.Digest)
		require.NoError(t, err)
		require.Equal(t, map[string]string{
			"custom": "keep", "containerd.io/gc.ref.content.l.0": manifest.Layers[0].Digest.String(),
			"containerd.io/gc.ref.content.config": manifest.Config.Digest.String(),
		}, gotLabels, "GC labels must retain only the rebuilt layers")
	}
	var original ocispec.Index
	require.NoError(t, oci.ReadJSON(ctx, store, source, &original))
	require.Equal(t, index, original, "source index and its platform markers must remain unchanged")
	originalLabels, err := oci.Labels(ctx, store, source.Digest)
	require.NoError(t, err)
	require.Equal(t, labels, originalLabels)
	broken := writeJSON(ocispec.Index{Manifests: []ocispec.Descriptor{
		index.Manifests[0],
		{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing second platform")},
	}}, ocispec.MediaTypeImageIndex, nil)
	got, err = ConvertToOCI(ctx, store, broken, ToOCIOption{BuilderPath: builder, WorkDir: scratch, Compressor: "oci-tar"})
	require.ErrorContains(t, err, "inspect manifest")
	require.Nil(t, got, "a later platform failure must not publish a partially converted index")
	entries, err := os.ReadDir(scratch)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestConvertToOCIIndexRejectsUnreadableContent(t *testing.T) {
	for _, kind := range []string{"missing index", "invalid index", "missing manifest", "invalid manifest", "missing blob"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			store, err := local.NewStore(t.TempDir())
			require.NoError(t, err)
			commit := func(data []byte, mediaType string) ocispec.Descriptor {
				dgst := digest.FromBytes(data)
				desc := ocispec.Descriptor{MediaType: mediaType, Digest: dgst, Size: int64(len(data))}
				require.NoError(t, content.WriteBlob(ctx, store, dgst.String(), bytes.NewReader(data), desc))
				return desc
			}
			source := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing")}
			want := "stat content"
			switch kind {
			case "invalid index":
				source = commit([]byte("{"), ocispec.MediaTypeImageIndex)
				want = "read index json"
			case "missing manifest", "invalid manifest", "missing blob":
				child := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing")}
				want = "inspect manifest"
				switch kind {
				case "invalid manifest":
					child = commit([]byte("{"), child.MediaType)
				case "missing blob":
					manifest := ocispec.Manifest{Layers: []ocispec.Descriptor{
						{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromString("missing-blob"),
							Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true"}},
						{MediaType: ocispec.MediaTypeImageLayerGzip,
							Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"}},
					}}
					desc, err := oci.WriteJSON(ctx, store, manifest, child, nil)
					require.NoError(t, err)
					child = *desc
					want = "convert manifest"
				}
				desc, err := oci.WriteJSON(ctx, store, ocispec.Index{Manifests: []ocispec.Descriptor{child}}, source, nil)
				require.NoError(t, err)
				source = *desc
			}
			scratch := t.TempDir()
			got, err := ConvertToOCI(ctx, store, source, ToOCIOption{WorkDir: scratch, Compressor: "oci-tar"})
			require.ErrorContains(t, err, want)
			require.Nil(t, got, "a failed platform must not publish an index")
			entries, err := os.ReadDir(scratch)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}
