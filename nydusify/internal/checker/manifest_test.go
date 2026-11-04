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
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func mockManifestImage() *nydusfs.Image {
	blob := ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromString("blob")}
	bootstrap := ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Digest:      digest.FromString("bootstrap"),
		Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
	}

	return &nydusfs.Image{
		Kind:      nydusfs.KindNydus,
		Bootstrap: &bootstrap,
		Manifest:  ocispec.Manifest{Layers: []ocispec.Descriptor{blob, bootstrap}},
		Config: ocispec.Image{
			Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"},
			Config:   ocispec.ImageConfig{Env: []string{"A=B"}, Cmd: []string{"run"}},
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{blob.Digest, digest.FromString("uncompressed bootstrap")}},
		},
	}
}

func TestManifestRule_Validate(t *testing.T) {
	tests := []struct {
		name   string
		single bool
		mock   func(img *nydusfs.Image)
		expect func(t *testing.T, err error)
	}{
		{
			name: "identical images",
			mock: func(img *nydusfs.Image) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "single image",
			single: true,
			mock:   func(img *nydusfs.Image) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "oci image",
			mock: func(img *nydusfs.Image) {
				img.Kind, img.Bootstrap = nydusfs.KindOCI, nil
				img.Manifest.Layers = img.Manifest.Layers[:1]
				img.Config.RootFS.DiffIDs = img.Config.RootFS.DiffIDs[:1]
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "rewritten diff ids and history",
			mock: func(img *nydusfs.Image) {
				img.Config.RootFS.DiffIDs = []digest.Digest{digest.FromString("new blob"), digest.FromString("new bootstrap")}
				img.Config.History = []ocispec.History{{CreatedBy: "nydus convert"}}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "nydus image without layers",
			mock: func(img *nydusfs.Image) {
				img.Manifest.Layers = nil
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus image has no layers")
			},
		},
		{
			name: "missing bootstrap",
			mock: func(img *nydusfs.Image) {
				img.Bootstrap = nil
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "the last layer is not a nydus bootstrap")
			},
		},
		{
			name: "bootstrap digest mismatch",
			mock: func(img *nydusfs.Image) {
				img.Bootstrap.Digest = digest.FromString("different bootstrap")
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "the last layer is not a nydus bootstrap")
			},
		},
		{
			name: "bootstrap before blob",
			mock: func(img *nydusfs.Image) {
				img.Manifest.Layers[0], img.Manifest.Layers[1] = img.Manifest.Layers[1], img.Manifest.Layers[0]
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is not the last layer")
			},
		},
		{
			name: "nydus diff id count mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.RootFS.DiffIDs = nil
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "does not match diff id count")
			},
		},
		{
			name: "oci diff id count mismatch",
			mock: func(img *nydusfs.Image) {
				img.Kind = nydusfs.KindOCI
				img.Config.RootFS.DiffIDs = nil
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "does not match diff id count")
			},
		},
		{
			name: "env mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.Config.Env = []string{"A=C"}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "image config")
			},
		},
		{
			name: "cmd mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.Config.Cmd = []string{"other"}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "image config")
			},
		},
		{
			name: "entrypoint mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.Config.Entrypoint = []string{"/bin/sh"}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "image config")
			},
		},
		{
			name: "working dir mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.Config.WorkingDir = "/work"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "image config")
			},
		},
		{
			name: "os mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.OS = "windows"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "os mismatch")
			},
		},
		{
			name: "architecture mismatch",
			mock: func(img *nydusfs.Image) {
				img.Config.Architecture = "arm64"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "architecture mismatch")
			},
		},
	}

	for _, tc := range tests {
		for _, side := range []string{"source", "target"} {
			t.Run(tc.name+" in "+side, func(t *testing.T) {
				img, other := mockManifestImage(), mockManifestImage()
				if tc.single {
					other = nil
				}

				tc.mock(img)
				rule := &manifestRule{source: img, target: other}
				if side == "target" {
					rule = &manifestRule{source: other, target: img}
				}

				tc.expect(t, rule.Validate(context.Background()))
			})
		}
	}
}
