/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// IsBlob reports whether desc is a converted nydus data blob layer.
func IsBlob(desc ocispec.Descriptor) bool {
	return desc.MediaType == MediaTypeNydusBlob
}

// IsBootstrap reports whether desc is a nydus bootstrap layer.
func IsBootstrap(desc ocispec.Descriptor) bool {
	if desc.Annotations == nil {
		return false
	}
	_, ok := desc.Annotations[LayerAnnotationNydusBootstrap]
	return ok
}

// IsOptimizedBlob reports whether desc is the ondemand blob appended by
// `nydusify optimize`, which carries no filesystem tree of its own.
func IsOptimizedBlob(desc ocispec.Descriptor) bool {
	if desc.Annotations == nil {
		return false
	}
	_, ok := desc.Annotations[LayerAnnotationNydusBlobOptimized]
	return ok
}

// SplitLayers classifies the layer list of a nydus image manifest according to
// the canonical layout `blob* [optimized-blob] bootstrap`: zero or more data
// blobs, optionally followed by the ondemand blob appended by `nydusify
// optimize`, terminated by the bootstrap layer, which must come last.
//
// Membership is decided solely by the Is* predicates, checked in this
// order: IsBootstrap (bootstrap annotation), IsOptimizedBlob
// (optimized annotation), IsBlob (nydus blob media type). In particular a
// data blob must carry the nydus blob media type; the legacy nydus-blob
// annotation alone does not qualify.
//
// bootstrap is nil (with a nil error) when every layer is a data blob — the
// pre-merge state produced by the layer converter before a bootstrap has been
// appended — and for an empty layer list. Any other deviation from the layout
// is an error.
func SplitLayers(layers []ocispec.Descriptor) (blobs []ocispec.Descriptor, bootstrap, optimized *ocispec.Descriptor, err error) {
	for i := range layers {
		layer := layers[i]
		switch {
		case IsBootstrap(layer):
			if i != len(layers)-1 {
				return nil, nil, nil, errors.Errorf("nydus bootstrap layer %s is not the last layer", layer.Digest)
			}
			bootstrap = &layer
		case IsOptimizedBlob(layer):
			if optimized != nil {
				return nil, nil, nil, errors.Errorf("more than one optimized ondemand blob layer (%s and %s)", optimized.Digest, layer.Digest)
			}
			optimized = &layer
		case IsBlob(layer):
			if optimized != nil {
				return nil, nil, nil, errors.Errorf("nydus data blob layer %s appears after the optimized ondemand blob", layer.Digest)
			}
			blobs = append(blobs, layer)
		default:
			return nil, nil, nil, errors.Errorf("layer %s (%s) is neither a nydus blob nor a nydus bootstrap", layer.Digest, layer.MediaType)
		}
	}
	return blobs, bootstrap, optimized, nil
}
