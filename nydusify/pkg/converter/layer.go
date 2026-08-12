/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// IsNydusBlob reports whether desc is a converted nydus data blob layer.
func IsNydusBlob(desc ocispec.Descriptor) bool {
	return desc.MediaType == MediaTypeNydusBlob
}

// IsNydusBootstrap reports whether desc is a nydus bootstrap layer.
func IsNydusBootstrap(desc ocispec.Descriptor) bool {
	if desc.Annotations == nil {
		return false
	}
	_, ok := desc.Annotations[LayerAnnotationNydusBootstrap]
	return ok
}

// IsNydusOptimizedBlob reports whether desc is the ondemand blob appended by
// `nydusify optimize`, which carries no filesystem tree of its own.
func IsNydusOptimizedBlob(desc ocispec.Descriptor) bool {
	if desc.Annotations == nil {
		return false
	}
	_, ok := desc.Annotations[LayerAnnotationNydusBlobOptimized]
	return ok
}
