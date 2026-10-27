/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestManifestRule(t *testing.T) {
	newImage := func() *nydusfs.Image {
		blob := ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromString("blob")}
		boot := ocispec.Descriptor{
			MediaType:   ocispec.MediaTypeImageLayerGzip,
			Digest:      digest.FromString("bootstrap"),
			Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
		}
		return &nydusfs.Image{
			Kind:      nydusfs.KindNydus,
			Bootstrap: &boot,
			Manifest:  ocispec.Manifest{Layers: []ocispec.Descriptor{blob, boot}},
			Config: ocispec.Image{
				Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"},
				Config:   ocispec.ImageConfig{Env: []string{"A=B"}, Cmd: []string{"run"}},
				RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{blob.Digest, digest.FromString("uncompressed bootstrap")}},
			},
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*nydusfs.Image)
		want   string
	}{
		{"equal", func(_ *nydusfs.Image) {}, ""},
		{"OCI", func(img *nydusfs.Image) {
			img.Kind, img.Bootstrap = nydusfs.KindOCI, nil
			img.Manifest.Layers = img.Manifest.Layers[:1]
			img.Config.RootFS.DiffIDs = img.Config.RootFS.DiffIDs[:1]
		}, ""},
		{"rewritten diff IDs and history", func(img *nydusfs.Image) {
			img.Config.RootFS.DiffIDs = []digest.Digest{digest.FromString("new blob"), digest.FromString("new bootstrap")}
			img.Config.History = []ocispec.History{{CreatedBy: "nydus convert"}}
		}, ""},
		{"no layers", func(img *nydusfs.Image) { img.Manifest.Layers = nil }, "nydus image has no layers"},
		{"missing bootstrap", func(img *nydusfs.Image) { img.Bootstrap = nil }, "the last layer is not a nydus bootstrap"},
		{"bootstrap digest", func(img *nydusfs.Image) {
			img.Bootstrap.Digest = digest.FromString("different bootstrap")
		}, "the last layer is not a nydus bootstrap"},
		{"bootstrap order", func(img *nydusfs.Image) {
			img.Manifest.Layers[0], img.Manifest.Layers[1] = img.Manifest.Layers[1], img.Manifest.Layers[0]
		}, "is not the last layer"},
		{"nydus diff ID count", func(img *nydusfs.Image) { img.Config.RootFS.DiffIDs = nil }, "does not match diff id count"},
		{"OCI diff ID count", func(img *nydusfs.Image) {
			img.Kind = nydusfs.KindOCI
			img.Config.RootFS.DiffIDs = nil
		}, "does not match diff id count"},
		{"environment", func(img *nydusfs.Image) { img.Config.Config.Env = []string{"A=C"} }, "image config"},
		{"command", func(img *nydusfs.Image) { img.Config.Config.Cmd = []string{"other"} }, "image config"},
		{"entrypoint", func(img *nydusfs.Image) { img.Config.Config.Entrypoint = []string{"/bin/sh"} }, "image config"},
		{"working directory", func(img *nydusfs.Image) { img.Config.Config.WorkingDir = "/work" }, "image config"},
		{"OS", func(img *nydusfs.Image) { img.Config.OS = "windows" }, "os mismatch"},
		{"architecture", func(img *nydusfs.Image) { img.Config.Architecture = "arm64" }, "architecture mismatch"},
	} {
		for _, side := range []string{"source", "target"} {
			t.Run(tc.name+"/"+side, func(t *testing.T) {
				rule := manifestRule{source: newImage(), target: newImage()}
				require.NoError(t, rule.Validate(context.Background()))
				if side == "source" {
					tc.change(rule.source)
				} else {
					tc.change(rule.target)
				}
				err := rule.Validate(context.Background())
				if tc.want == "" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, tc.want)
				}
			})
		}
	}
	t.Run("single image", func(t *testing.T) {
		for _, rule := range []manifestRule{{source: newImage()}, {target: newImage()}} {
			require.NoError(t, rule.Validate(context.Background()))
		}
	})
}
