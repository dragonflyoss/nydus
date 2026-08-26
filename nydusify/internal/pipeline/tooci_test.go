/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"

	"github.com/containerd/containerd/v2/pkg/archive/compression"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestRewriteOCIConfigResetsDiffIDsAndTrimsHistory verifies that the reverse
// conversion restores an ordinary OCI config: the rebuilt layers get fresh
// diff ids, the history entries of the removed layers are gone, and every
// other field survives untouched.
func TestRewriteOCIConfigResetsDiffIDsAndTrimsHistory(t *testing.T) {
	source := []byte(`{
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
	}`)
	diffIDs := []digest.Digest{
		"sha256:aaaa6f54a6fbd8e0cb80e9d9ee92d86cf5bd06c1424375c3cdde4acce16d6fc0",
		"sha256:bbbb6f54a6fbd8e0cb80e9d9ee92d86cf5bd06c1424375c3cdde4acce16d6fc0",
	}

	out, err := rewriteOCIConfig(source, diffIDs, 2)
	if err != nil {
		t.Fatalf("rewriteOCIConfig: %v", err)
	}

	var got, want map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if err := json.Unmarshal(source, &want); err != nil {
		t.Fatalf("unmarshal source: %v", err)
	}
	// Marshaling compacts every raw message, so compare the compacted forms.
	var gotConfig, wantConfig bytes.Buffer
	if err := json.Compact(&gotConfig, got["config"]); err != nil {
		t.Fatalf("compact result config: %v", err)
	}
	if err := json.Compact(&wantConfig, want["config"]); err != nil {
		t.Fatalf("compact source config: %v", err)
	}
	if gotConfig.String() != wantConfig.String() {
		t.Errorf("runtime config = %s, want %s", gotConfig.String(), wantConfig.String())
	}

	var rootFS ocispec.RootFS
	if err := json.Unmarshal(got["rootfs"], &rootFS); err != nil {
		t.Fatalf("unmarshal rootfs: %v", err)
	}
	if !reflect.DeepEqual(rootFS.DiffIDs, diffIDs) {
		t.Errorf("diff ids = %v, want %v", rootFS.DiffIDs, diffIDs)
	}

	var history []ocispec.History
	if err := json.Unmarshal(got["history"], &history); err != nil {
		t.Fatalf("unmarshal history: %v", err)
	}
	// The two trailing entries describe removed layers; the empty-layer entry
	// consumes no layer and must survive.
	wantHistory := []string{"RUN apt-get update", "ENV PATH=/usr/bin", "COPY app /app"}
	if len(history) != len(wantHistory) {
		t.Fatalf("history = %+v, want %v", history, wantHistory)
	}
	for i, createdBy := range wantHistory {
		if history[i].CreatedBy != createdBy {
			t.Errorf("history[%d].created_by = %q, want %q", i, history[i].CreatedBy, createdBy)
		}
	}
}

func TestNydusDataLayersSkipsBootstrapAndOptimizedBlobs(t *testing.T) {
	blob := func(dgst string, extra ...string) ocispec.Descriptor {
		annotations := map[string]string{nydus.LayerAnnotationNydusBlob: "true"}
		for _, name := range extra {
			annotations[name] = "true"
		}
		return ocispec.Descriptor{
			MediaType:   nydus.MediaTypeNydusBlob,
			Digest:      digest.Digest(dgst),
			Annotations: annotations,
		}
	}
	bootstrap := ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
	}
	oci := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip}

	if _, err := nydusDataLayers([]ocispec.Descriptor{oci}); err == nil {
		t.Error("expected an error for a plain OCI layer")
	}
	if _, err := nydusDataLayers([]ocispec.Descriptor{blob("sha256:a")}); err == nil {
		t.Error("expected an error when the bootstrap layer is missing")
	}

	blobs, err := nydusDataLayers([]ocispec.Descriptor{
		blob("sha256:a"),
		blob("sha256:b"),
		blob("sha256:c", nydus.LayerAnnotationNydusBlobOptimized),
		bootstrap,
	})
	if err != nil {
		t.Fatalf("nydusDataLayers: %v", err)
	}
	if len(blobs) != 2 || blobs[0].Digest != "sha256:a" || blobs[1].Digest != "sha256:b" {
		t.Errorf("data layers = %v, want the two plain data blobs in order", blobs)
	}
}

func TestParseCompressorAndLayerMediaType(t *testing.T) {
	cases := map[string]struct {
		algo      compression.Compression
		mediaType string
	}{
		"oci-gzip": {compression.Gzip, ocispec.MediaTypeImageLayerGzip},
		"oci-zstd": {compression.Zstd, ocispec.MediaTypeImageLayerZstd},
		"oci-tar":  {compression.Uncompressed, ocispec.MediaTypeImageLayer},
	}
	for name, want := range cases {
		if !IsOCICompressor(name) {
			t.Errorf("IsOCICompressor(%q) = false, want true", name)
		}
		algo, err := parseCompressor(name)
		if err != nil {
			t.Fatalf("parseCompressor(%q): %v", name, err)
		}
		if algo != want.algo {
			t.Errorf("parseCompressor(%q) = %v, want %v", name, algo, want.algo)
		}
		if got := layerMediaType(algo); got != want.mediaType {
			t.Errorf("layerMediaType(%q) = %q, want %q", name, got, want.mediaType)
		}
	}
	// The forward compressors must not be mistaken for a reverse conversion.
	for _, name := range []string{"", "zstd", "none", "gzip"} {
		if IsOCICompressor(name) {
			t.Errorf("IsOCICompressor(%q) = true, want false", name)
		}
		if _, err := parseCompressor(name); err == nil {
			t.Errorf("parseCompressor(%q) succeeded, want an error", name)
		}
	}
}

func TestStripNydusOSFeature(t *testing.T) {
	platform := &ocispec.Platform{
		OS:         "linux",
		OSFeatures: []string{nydus.ManifestOSFeatureNydus, "other"},
	}
	got := stripNydusOSFeature(platform)
	if !reflect.DeepEqual(got.OSFeatures, []string{"other"}) {
		t.Errorf("os features = %v, want [other]", got.OSFeatures)
	}
	if len(platform.OSFeatures) != 2 {
		t.Error("stripNydusOSFeature must not mutate its input")
	}
	if stripNydusOSFeature(nil) != nil {
		t.Error("nil platform must stay nil")
	}
}

func TestPruneLayerGCLabels(t *testing.T) {
	labels := map[string]string{
		"containerd.io/gc.ref.content.l.0":   "sha256:a",
		"containerd.io/gc.ref.content.l.12":  "sha256:b",
		"containerd.io/gc.ref.content.confi": "keep",
	}
	pruneLayerGCLabels(labels)
	if len(labels) != 1 {
		t.Errorf("labels = %v, want only the non-layer label", labels)
	}
}
