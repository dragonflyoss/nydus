/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestConvertHookAnnotatesUnchangedNydusManifest(t *testing.T) {
	ctx := context.Background()
	store, err := local.NewStore(filepath.Join(t.TempDir(), "content"))
	if err != nil {
		t.Fatal(err)
	}

	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Layers: []ocispec.Descriptor{
			{
				MediaType: nydus.MediaTypeNydusBlob,
				Digest:    digest.FromString("blob"),
				Annotations: map[string]string{
					nydus.LayerAnnotationNydusBlob: "true",
				},
			},
			{
				MediaType: ocispec.MediaTypeImageLayerGzip,
				Digest:    digest.FromString("bootstrap"),
				Annotations: map[string]string{
					nydus.LayerAnnotationNydusBootstrap: "true",
				},
			},
		},
		Annotations: map[string]string{"org.example.existing": "keep"},
	}
	desc, err := oci.WriteJSON(ctx, store, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	desc.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}

	hook := ConvertHookFunc(nydus.MergeOption{}, map[string]string{
		"org.example.existing": "override",
		"org.example.added":    "value",
	})
	gotDesc, err := hook(ctx, store, *desc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotDesc == nil || gotDesc.Digest == desc.Digest {
		t.Fatalf("rewritten descriptor = %+v, original digest = %s", gotDesc, desc.Digest)
	}
	if !reflect.DeepEqual(gotDesc.Platform, desc.Platform) {
		t.Fatalf("platform = %+v, want %+v", gotDesc.Platform, desc.Platform)
	}

	var got ocispec.Manifest
	if err := oci.ReadJSON(ctx, store, *gotDesc, &got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations["org.example.existing"] != "override" || got.Annotations["org.example.added"] != "value" {
		t.Fatalf("annotations = %v", got.Annotations)
	}

	manifest.Layers = []ocispec.Descriptor{{MediaType: ocispec.MediaTypeImageLayerGzip}}
	ordinaryDesc, err := oci.WriteJSON(ctx, store, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := hook(ctx, store, *ordinaryDesc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != nil {
		t.Fatalf("ordinary manifest was unexpectedly rewritten: %+v", unchanged)
	}
}

// TestRewriteBootstrapConfigPreservesRuntimeConfig verifies that rewriting the
// image config for the bootstrap layer only changes the diff ids and history
// while leaving the runtime config (env/cmd/entrypoint/working dir/etc.)
// identical to the source. This guards the `nydusify check` config-consistency
// rule, which compares the source and target configs with reflect.DeepEqual.
func TestRewriteBootstrapConfigPreservesRuntimeConfig(t *testing.T) {
	// A config whose runtime fields include empty-but-present values. These are
	// exactly the cases a naive ocispec.Image round-trip drops via `omitempty`,
	// turning `"Cmd": []` into a nil slice and breaking DeepEqual.
	source := []byte(`{
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
	}`)

	newDiffIDs := []digest.Digest{
		"sha256:ce4fb534c921482313d6d261b1f1365c8dd2f46f536ad6d12bbefa86404cc928",
		"sha256:7fe968f0b648e72a5c413a2780606a7896b4433ff1d9d0514a75f2cb5e83aaeb",
	}

	out, err := rewriteBootstrapConfig(source, newDiffIDs)
	if err != nil {
		t.Fatalf("rewriteBootstrapConfig: %v", err)
	}

	var srcImg, dstImg ocispec.Image
	if err := json.Unmarshal(source, &srcImg); err != nil {
		t.Fatalf("unmarshal source: %v", err)
	}
	if err := json.Unmarshal(out, &dstImg); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}

	// The runtime config must be byte-for-byte equivalent so the consistency
	// rule (reflect.DeepEqual on Config.Config) passes.
	if !reflect.DeepEqual(srcImg.Config, dstImg.Config) {
		t.Errorf("runtime config changed:\n source: %#v\n target: %#v", srcImg.Config, dstImg.Config)
	}
	if srcImg.OS != dstImg.OS || srcImg.Architecture != dstImg.Architecture {
		t.Errorf("platform changed: source os=%q arch=%q target os=%q arch=%q",
			srcImg.OS, srcImg.Architecture, dstImg.OS, dstImg.Architecture)
	}

	// The diff ids must be replaced with the bootstrap layer set.
	if !reflect.DeepEqual(dstImg.RootFS.DiffIDs, newDiffIDs) {
		t.Errorf("diff ids = %v, want %v", dstImg.RootFS.DiffIDs, newDiffIDs)
	}

	// A bootstrap history entry must be appended to the existing history.
	if len(dstImg.History) != len(srcImg.History)+1 {
		t.Fatalf("history length = %d, want %d", len(dstImg.History), len(srcImg.History)+1)
	}
	last := dstImg.History[len(dstImg.History)-1]
	if last.CreatedBy != "Nydus Converter" || last.Comment != "Nydus Bootstrap Layer" {
		t.Errorf("unexpected bootstrap history entry: %#v", last)
	}
}

// TestRewriteBootstrapConfigKeepsUnknownFields verifies that fields the nydus
// converter does not model (e.g. Docker's legacy top-level keys) survive the
// rewrite, so the converted config does not silently lose data.
func TestRewriteBootstrapConfigKeepsUnknownFields(t *testing.T) {
	source := []byte(`{
		"architecture": "arm64",
		"os": "linux",
		"variant": "v8",
		"config": {"Cmd": ["sh"]},
		"rootfs": {"type": "layers", "diff_ids": []},
		"custom_top_level": {"keep": "me"}
	}`)

	out, err := rewriteBootstrapConfig(source, []digest.Digest{"sha256:d1e78ae50d261a4661b0d2948fb0edd83a30482192d5a2ca8d350797ce8b6d36"})
	if err != nil {
		t.Fatalf("rewriteBootstrapConfig: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}
	if _, ok := raw["custom_top_level"]; !ok {
		t.Errorf("unknown top-level field was dropped: %s", out)
	}
	if _, ok := raw["variant"]; !ok {
		t.Errorf("variant field was dropped: %s", out)
	}
}

func TestConvertHookFunc(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		descs       func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor)
		expect      func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "ignores unconverted layer",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				return mockGzipLayer, nil
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "returns converted layer",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				blob := writeMockBlob(t, cs, "converted blob")
				return mockGzipLayer, &blob
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(newDesc, desc)
			},
		},
		{
			name: "collapses single manifest index",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				index := writeMockImage(t, cs, mockPlatform)
				return index, &index
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(ocispec.MediaTypeImageManifest, desc.MediaType)
				assert.Equal(&mockPlatform, desc.Platform)
			},
		},
		{
			name: "keeps multi manifest index",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				index := writeMockImage(t, cs, mockPlatform, mockARM64Platform)
				return index, &index
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(newDesc, desc)
			},
		},
		{
			name: "rejects unreadable index",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				index := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing index")}
				return index, &index
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read index json")
				assert.Nil(desc)
			},
		},
		{
			name:        "keeps attestation manifest unannotated",
			annotations: mockManifestAnnotations,
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				manifest := writeMockManifest(t, cs, ocispec.Descriptor{MediaType: "application/vnd.in-toto+json", Digest: digest.FromString("attestation")})
				return manifest, &manifest
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(newDesc, desc)
			},
		},
		{
			name:        "rejects unreadable manifest to annotate",
			annotations: mockManifestAnnotations,
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing manifest")}, nil
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read manifest json")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects merge of missing blob",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				manifest := writeMockManifest(t, cs, ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromString("missing blob")})
				return manifest, &manifest
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "merge nydus layers: open blob")
				assert.Nil(desc)
			},
		},
		{
			name: "rejects merge of invalid blob",
			descs: func(t *testing.T, cs content.Store) (ocispec.Descriptor, *ocispec.Descriptor) {
				manifest := writeMockManifest(t, cs, writeMockBlob(t, cs, "invalid blob"))
				return manifest, &manifest
			},
			expect: func(t *testing.T, newDesc, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "merge nydus layers: stage blob")
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := newMockStore(t)
			orgDesc, newDesc := tc.descs(t, cs)
			desc, err := ConvertHookFunc(nydus.MergeOption{WorkDir: t.TempDir()}, tc.annotations)(context.Background(), cs, orgDesc, newDesc)
			tc.expect(t, newDesc, desc, err)
		})
	}
}
