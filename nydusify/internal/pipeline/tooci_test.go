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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"

	"github.com/containerd/containerd/v2/pkg/archive/compression"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

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
	// The fixture must reach the exporter as an intact, digest-named blob.
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

func TestConvertToOCIParallelFailure(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run parallel export failure tests")
	}
	oldProcs := runtime.GOMAXPROCS(max(2, runtime.GOMAXPROCS(0)))
	defer runtime.GOMAXPROCS(oldProcs)
	for _, mode := range []string{"layer_failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			work := t.TempDir()
			store, err := local.NewStore(filepath.Join(work, "content"))
			if err != nil {
				t.Fatal(err)
			}
			scratch, control := filepath.Join(work, "scratch"), filepath.Join(work, "control")
			for _, path := range []string{scratch, control} {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			var blobs []ocispec.Descriptor
			for _, name := range []string{"lower", "upper"} {
				var source bytes.Buffer
				writer := tar.NewWriter(&source)
				data := []byte(name + " layer payload")
				if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				dgst, size, err := oci.CommitBlob(ctx, store, name, "", nil, func(w io.Writer) error {
					_, err := w.Write(source.Bytes())
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				converted, err := convertLayer(ctx, store, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: dgst, Size: size},
					nydus.PackOption{BuilderPath: builder, WorkDir: work})
				if err != nil {
					t.Fatal(err)
				}
				blobs = append(blobs, *converted)
			}
			config, err := oci.WriteJSON(ctx, store, ocispec.Image{RootFS: ocispec.RootFS{Type: "layers"}},
				ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap, err := oci.WriteBootstrapLayer(ctx, store, []byte("unused by per-layer export"), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			source, err := oci.WriteJSON(ctx, store, ocispec.Manifest{Config: *config, Layers: append(slices.Clone(blobs), *bootstrap)},
				ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
			if err != nil {
				t.Fatal(err)
			}
			before := make(map[digest.Digest]bool)
			if err := store.Walk(ctx, func(info content.Info) error { before[info.Digest] = true; return nil }); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			exporter := filepath.Join(work, "exporter")
			if err := os.WriteFile(exporter, []byte(fmt.Sprintf("#!/bin/sh\nexec %q -test.run=^TestExportChild$ -- \"$@\"\n", executable)), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("NYDUS_EXPORT_CONTROL", control)
			t.Setenv("NYDUS_EXPORT_FAIL", blobs[0].Digest.Encoded())
			type result struct {
				desc *ocispec.Descriptor
				err  error
			}
			done := make(chan result, 1)
			go func() {
				desc, err := ConvertToOCI(ctx, store, *source, ToOCIOption{BuilderPath: exporter, WorkDir: scratch, Compressor: "oci-tar"})
				done <- result{desc, err}
				close(done)
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
			if mode == "cancel" {
				cancel()
			} else if err := os.WriteFile(filepath.Join(control, "release"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				if result.desc != nil || result.err == nil || !strings.Contains(result.err.Error(), "unpack nydus layer") {
					t.Fatalf("conversion published a result or lost error context: %+v", result)
				}
				if mode == "layer_failure" && (!strings.Contains(result.err.Error(), "injected export failure") ||
					!strings.Contains(result.err.Error(), blobs[0].Digest.String()) || ctx.Err() != nil) {
					t.Fatalf("initiating failure was lost or cancellation hung: %v", result.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("export failed to cancel and reap peers within 5s")
			}
			for _, pid := range pids {
				if err := unix.Kill(pid, 0); err != unix.ESRCH {
					t.Errorf("export child %d not reaped: %v", pid, err)
				}
			}
			entries, err := os.ReadDir(scratch)
			if err != nil || len(entries) != 0 {
				t.Errorf("materialized blobs leaked: %v, %v", entries, err)
			}
			if err := store.Walk(context.Background(), func(info content.Info) error {
				if !before[info.Digest] {
					t.Errorf("failed conversion committed partial content: %s", info.Digest)
				}
				delete(before, info.Digest)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(before) != 0 {
				t.Errorf("failed conversion removed source content: %v", before)
			}
		})
	}
}

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
