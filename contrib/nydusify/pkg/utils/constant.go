// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

const (
	ManifestOSFeatureNydus   = "nydus.remoteimage.v1"
	MediaTypeNydusBlob       = "application/vnd.oci.image.layer.nydus.blob.v1"
	BootstrapFileNameInLayer = "image/image.boot"
	ManifestNydusCache       = "containerd.io/snapshot/nydus-cache"
	ManifestNydusCacheV1     = "v1"

	LayerAnnotationNydusBlob      = "containerd.io/snapshot/nydus-blob"
	LayerAnnotationNydusBlobIDs   = "containerd.io/snapshot/nydus-blob-ids"
	LayerAnnotationNydusBootstrap = "containerd.io/snapshot/nydus-bootstrap"
	LayerAnnotationNydusSignature = "containerd.io/snapshot/nydus-signature"

	LayerAnnotationNydusSourceChainID = "containerd.io/snapshot/nydus-source-chainid"
	LayerAnnotationNydusBlobDigest    = "containerd.io/snapshot/nydus-blob-digest"
	LayerAnnotationNydusBlobSize      = "containerd.io/snapshot/nydus-blob-size"
	LayerAnnotationNydusRafsVersion   = "containerd.io/snapshot/nydus-rafs-version"

	LayerAnnotationUncompressed = "containerd.io/uncompressed"
)
