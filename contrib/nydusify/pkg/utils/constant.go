// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

const (
	ManifestOSFeatureNydus   = "nydus.remoteimage.v1"
	MediaTypeNydusBlob       = "application/vnd.oci.image.layer.nydus.blob.v1"
	BootstrapFileNameInLayer = "image/image.boot"

	ManifestNydusCache = "containerd.io/snapshot/nydus-cache"

	LayerAnnotationNydusBlob          = "containerd.io/snapshot/nydus-blob"
	LayerAnnotationNydusBlobDigest    = "containerd.io/snapshot/nydus-blob-digest"
	LayerAnnotationNydusBlobSize      = "containerd.io/snapshot/nydus-blob-size"
	LayerAnnotationNydusBootstrap     = "containerd.io/snapshot/nydus-bootstrap"
	LayerAnnotationNydusFsVersion     = "containerd.io/snapshot/nydus-fs-version"
	LayerAnnotationNydusSourceChainID = "containerd.io/snapshot/nydus-source-chainid"
	LayerAnnotationNydusEncryptedBlob = "containerd.io/snapshot/nydus-encrypted-blob"

	LayerAnnotationNydusReferenceBlobIDs = "containerd.io/snapshot/nydus-reference-blob-ids"

	LayerAnnotationUncompressed = "containerd.io/uncompressed"
)
