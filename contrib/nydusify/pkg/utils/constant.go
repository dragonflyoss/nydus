// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

const (
	ArtifactTypeNydusImageManifest = "application/vnd.nydus.image.manifest.v1+json"
	ManifestOSFeatureNydus         = "nydus.remoteimage.v1"
	MediaTypeNydusBlob             = "application/vnd.oci.image.layer.nydus.blob.v1"
	BootstrapFileNameInLayer       = "image/image.boot"
	BackendFileNameInLayer         = "image/backend.json"

	ManifestNydusCache = "containerd.io/snapshot/nydus-cache"

	LayerAnnotationNydusBlob          = "containerd.io/snapshot/nydus-blob"
	LayerAnnotationNydusBlobDigest    = "containerd.io/snapshot/nydus-blob-digest"
	LayerAnnotationNydusBlobSize      = "containerd.io/snapshot/nydus-blob-size"
	LayerAnnotationNydusBootstrap     = "containerd.io/snapshot/nydus-bootstrap"
	LayerAnnotationNydusFsVersion     = "containerd.io/snapshot/nydus-fs-version"
	LayerAnnotationNydusSourceChainID = "containerd.io/snapshot/nydus-source-chainid"
	LayerAnnotationNydusArtifactType  = "containerd.io/snapshot/nydus-artifact-type"

	LayerAnnotationNydusReferenceBlobIDs = "containerd.io/snapshot/nydus-reference-blob-ids"

	LayerAnnotationUncompressed = "containerd.io/uncompressed"

	LayerAnnotationNydusCommitBlobs  = "containerd.io/snapshot/nydus-commit-blobs"
	LayerAnnotationNyudsPrefetchBlob = "containerd.io/snapshot/nydus-separated-blob-with-prefetch-files"
)
