/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package optimizer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestNewOptimizerTraceFileValidation(t *testing.T) {
	base := OptimizeOption{Source: "localhost:5000/src:v3", Target: "localhost:5000/dst:v3"}

	// Trace file missing.
	if _, err := NewOptimizer(base); err == nil ||
		!strings.Contains(err.Error(), "trace file must be provided") {
		t.Fatalf("expected missing-trace-file error, got %v", err)
	}

	// Trace file provided.
	withTraceFile := base
	withTraceFile.TraceFile = "/tmp/trace.json"
	o, err := NewOptimizer(withTraceFile)
	if err != nil {
		t.Fatalf("trace file should be accepted: %v", err)
	}
	if o.opt.TraceFile != "/tmp/trace.json" {
		t.Fatalf("unexpected opt normalization: %+v", o.opt)
	}
}

func TestIngestDigestNamedBlobFile(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch_%v", mismatch), func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			store, err := local.NewStore(filepath.Join(dir, "content"))
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("ondemand payload")
			expected := digest.FromBytes(data)
			if mismatch {
				expected = digest.FromString("different payload")
			}
			path := filepath.Join(dir, expected.Encoded())
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			desc, err := ingestDigestNamedBlobFile(ctx, store, path)
			if mismatch {
				if err == nil || desc != nil || !strings.Contains(err.Error(), "unexpected commit digest") {
					t.Fatalf("mismatched blob = %v, %v", desc, err)
				}
				for _, dgst := range []digest.Digest{expected, digest.FromBytes(data)} {
					if _, err := store.Info(ctx, dgst); !errdefs.IsNotFound(err) {
						t.Fatalf("mismatched content published as %s: %v", dgst, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := content.ReadBlob(ctx, store, *desc)
			if err != nil || string(got) != string(data) || desc.Digest != expected ||
				desc.Annotations[nydus.LayerAnnotationNydusBlobOptimized] != "true" ||
				desc.Annotations[nydus.LayerAnnotationUncompressed] != expected.String() {
				t.Fatalf("blob = %+v, %q, %v", desc, got, err)
			}
		})
	}
}

func TestWriteOptimizedImage(t *testing.T) {
	for _, tc := range []struct {
		name, missing, wantError string
		fallback, previous       bool
	}{
		{name: "annotations"},
		{name: "config_diffid_fallback", fallback: true},
		{name: "previous_ondemand", fallback: true, previous: true},
		{name: "missing_source_diffid", fallback: true, missing: "source", wantError: "cannot determine diff id"},
		{name: "missing_ondemand_annotation", missing: "ondemand", wantError: "missing uncompressed annotation on appended layer"},
		{name: "missing_bootstrap_annotation", missing: "bootstrap", wantError: "missing uncompressed annotation on appended layer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			store := provider.ContentStore()
			blob := func(name string) ocispec.Descriptor {
				dgst := digest.FromString(name)
				return ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: dgst, Annotations: map[string]string{
					nydus.LayerAnnotationNydusBlob: "true", nydus.LayerAnnotationUncompressed: dgst.String(),
				}}
			}
			data, previous, ondemand := blob("data"), blob("previous"), blob("ondemand")
			previous.Annotations[nydus.LayerAnnotationNydusBlobOptimized] = "true"
			ondemand.Annotations[nydus.LayerAnnotationNydusBlobOptimized] = "true"
			bootstrap := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("bootstrap"), Annotations: map[string]string{
				nydus.LayerAnnotationNydusBootstrap: "true", nydus.LayerAnnotationUncompressed: digest.FromString("bootstrap tar").String(),
			}}
			img := &nydusfs.Image{
				Desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
				Config: ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromString("original diffid")}},
					Config: ocispec.ImageConfig{Env: []string{"KEY=value"}}, History: []ocispec.History{{CreatedBy: "source"}}},
				Manifest: ocispec.Manifest{Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
					Layers: []ocispec.Descriptor{data}, Annotations: map[string]string{"example.test/source": "retained"}},
			}
			wantLayers := []ocispec.Descriptor{data}
			wantDiffIDs := []digest.Digest{data.Digest}
			if tc.fallback {
				delete(data.Annotations, nydus.LayerAnnotationUncompressed)
				wantDiffIDs[0] = img.Config.RootFS.DiffIDs[0]
			}
			if tc.previous {
				delete(previous.Annotations, nydus.LayerAnnotationUncompressed)
				img.Manifest.Layers = append(img.Manifest.Layers, previous)
				img.Config.RootFS.DiffIDs = append(img.Config.RootFS.DiffIDs, previous.Digest)
				wantLayers = append(wantLayers, previous)
				wantDiffIDs = append(wantDiffIDs, previous.Digest)
			}
			oldBootstrap := bootstrap
			oldBootstrap.Digest = digest.FromString("old bootstrap")
			img.Manifest.Layers = append(img.Manifest.Layers, oldBootstrap)
			if tc.missing == "source" {
				img.Config.RootFS.DiffIDs = nil
			}
			if tc.missing == "ondemand" {
				delete(ondemand.Annotations, nydus.LayerAnnotationUncompressed)
			}
			if tc.missing == "bootstrap" {
				delete(bootstrap.Annotations, nydus.LayerAnnotationUncompressed)
			}
			desc, err := (&Optimizer{}).writeOptimizedImage(ctx, store, img, ondemand, bootstrap)
			if tc.wantError != "" {
				if err == nil || desc != nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("result = %v, %v, want %q", desc, err, tc.wantError)
				}
				count := 0
				if err := store.Walk(ctx, func(content.Info) error { count++; return nil }); (err != nil && !os.IsNotExist(err)) || count != 0 {
					t.Fatalf("invalid image published %d blobs: %v", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var manifest ocispec.Manifest
			if err := oci.ReadJSON(ctx, store, *desc, &manifest); err != nil {
				t.Fatal(err)
			}
			wantLayers = append(wantLayers, ondemand, bootstrap)
			wantDiffIDs = append(wantDiffIDs, ondemand.Digest, digest.Digest(bootstrap.Annotations[nydus.LayerAnnotationUncompressed]))
			if !reflect.DeepEqual(manifest.Layers, wantLayers) || !reflect.DeepEqual(manifest.Annotations, img.Manifest.Annotations) ||
				!reflect.DeepEqual(desc.Platform, img.Desc.Platform) {
				t.Fatalf("manifest changed retained fields: %+v", manifest)
			}
			var config ocispec.Image
			if err := oci.ReadJSON(ctx, store, manifest.Config, &config); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(config.RootFS.DiffIDs, wantDiffIDs) || !reflect.DeepEqual(config.Config, img.Config.Config) ||
				len(config.History) != 2 || config.History[0] != img.Config.History[0] || config.History[1].CreatedBy != "Nydus Optimizer" {
				t.Fatalf("config = %+v", config)
			}
			labels, err := oci.Labels(ctx, store, desc.Digest)
			if err != nil {
				t.Fatal(err)
			}
			for i, layer := range wantLayers {
				if labels["containerd.io/gc.ref.content.l."+strconv.Itoa(i)] != layer.Digest.String() {
					t.Errorf("layer %d missing GC reference", i)
				}
			}
			if labels["containerd.io/gc.ref.content.config"] != manifest.Config.Digest.String() {
				t.Error("config missing GC reference")
			}
		})
	}
}
