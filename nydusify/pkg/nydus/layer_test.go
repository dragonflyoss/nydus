/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

var (
	mockBlobLayer = ocispec.Descriptor{
		MediaType: MediaTypeNydusBlob,
		Digest:    digest.FromString("blob"),
	}

	mockOtherBlobLayer = ocispec.Descriptor{
		MediaType: MediaTypeNydusBlob,
		Digest:    digest.FromString("other blob"),
	}

	mockOptimizedLayer = ocispec.Descriptor{
		MediaType:   MediaTypeNydusBlob,
		Digest:      digest.FromString("optimized"),
		Annotations: map[string]string{LayerAnnotationNydusBlobOptimized: "true"},
	}

	mockBootstrapLayer = ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Digest:      digest.FromString("bootstrap"),
		Annotations: map[string]string{LayerAnnotationNydusBootstrap: "true"},
	}

	mockOCILayer = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("oci"),
	}
)

func TestSplitLayers(t *testing.T) {
	tests := []struct {
		name   string
		layers []ocispec.Descriptor
		expect func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error)
	}{
		{
			name: "empty layer list",
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
				assert.Nil(bootstrap)
				assert.Nil(optimized)
			},
		},
		{
			name:   "data blobs before merge",
			layers: []ocispec.Descriptor{mockBlobLayer, mockOtherBlobLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobLayer, mockOtherBlobLayer}, blobs)
				assert.Nil(bootstrap)
				assert.Nil(optimized)
			},
		},
		{
			name:   "canonical optimized layout",
			layers: []ocispec.Descriptor{mockBlobLayer, mockOptimizedLayer, mockBootstrapLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobLayer}, blobs)
				assert.Equal(&mockBootstrapLayer, bootstrap)
				assert.Equal(&mockOptimizedLayer, optimized)
			},
		},
		{
			name:   "bootstrap not last",
			layers: []ocispec.Descriptor{mockBootstrapLayer, mockBlobLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is not the last layer")
				assert.Nil(blobs)
				assert.Nil(bootstrap)
			},
		},
		{
			name:   "two optimized blobs",
			layers: []ocispec.Descriptor{mockOptimizedLayer, mockOptimizedLayer, mockBootstrapLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "more than one optimized ondemand blob layer")
				assert.Nil(optimized)
			},
		},
		{
			name:   "data blob after optimized blob",
			layers: []ocispec.Descriptor{mockOptimizedLayer, mockBlobLayer, mockBootstrapLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "appears after the optimized ondemand blob")
				assert.Nil(blobs)
			},
		},
		{
			name:   "plain oci layer",
			layers: []ocispec.Descriptor{mockOCILayer, mockBootstrapLayer},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is neither a nydus blob nor a nydus bootstrap")
				assert.ErrorContains(err, mockOCILayer.Digest.String())
			},
		},
		{
			name: "legacy blob annotation without blob media type",
			layers: []ocispec.Descriptor{{
				MediaType:   ocispec.MediaTypeImageLayerGzip,
				Digest:      digest.FromString("legacy"),
				Annotations: map[string]string{LayerAnnotationNydusBlob: "true"},
			}},
			expect: func(t *testing.T, blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is neither a nydus blob nor a nydus bootstrap")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blobs, bootstrap, optimized, err := SplitLayers(tc.layers)

			tc.expect(t, blobs, bootstrap, optimized, err)
		})
	}
}
