/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package converter exposes the reusable pieces of the nydus image
// conversion pipeline: media type and annotation constants, `nydus
// build` / `nydus merge` invocation helpers, full blob footer parsing,
// and store-agnostic streaming Pack / Merge entry points designed for
// integration into external build systems (e.g. buildkit).
package converter

// Media types and annotations used by nydus images.
//
// The on-wire manifest format intentionally mirrors the nydus image format so
// that existing snapshotters and tooling that already understand the nydus
// layout can consume nydus images with minimal changes.
const (
	// ManifestOSFeatureNydus marks a platform manifest in an image index as a
	// remote (lazy-loadable) nydus image.
	ManifestOSFeatureNydus = "nydus.remoteimage.v1"

	// MediaTypeNydusBlob is the media type of a single converted data layer
	// (a nydus full blob: data + bootstrap + blob meta + footer).
	MediaTypeNydusBlob = "application/vnd.oci.image.layer.nydus.blob.v1"

	// BootstrapFileNameInLayer is the path of the bootstrap entry inside the
	// gzip-compressed bootstrap layer tarball.
	BootstrapFileNameInLayer = "image/image.boot"

	// BlobMetaDirInLayer is the directory inside the bootstrap layer tarball
	// that holds the per-layer `<full_blob_sha256>.blob.meta` artifacts, packed
	// alongside image.boot.
	BlobMetaDirInLayer = "image"

	// LayerAnnotationNydusBlob marks a layer as a nydus data blob.
	LayerAnnotationNydusBlob = "containerd.io/snapshot/nydus-blob"
	// LayerAnnotationNydusBootstrap marks a layer as the nydus bootstrap.
	LayerAnnotationNydusBootstrap = "containerd.io/snapshot/nydus-bootstrap"
	// LayerAnnotationNydusFsVersion marks a bootstrap layer as a nydus pmem
	// image for snapshotters that dispatch by nydus fs-version annotations.
	LayerAnnotationNydusFsVersion = "containerd.io/snapshot/nydus-fs-version"
	// NydusFsVersion is the pseudo nydus fs-version used for nydus pmem images.
	NydusFsVersion = "7"

	// LayerAnnotationUncompressed holds the uncompressed digest (diff id) of a
	// layer, following the containerd convention.
	LayerAnnotationUncompressed = "containerd.io/uncompressed"
)

// Default conversion parameters applied when the corresponding option is zero.
const (
	// DefaultChunkSize is the default nydus file chunk size in bytes.
	DefaultChunkSize = 1 << 20
	// DefaultCompressSize is the default group uncompressed size in bytes.
	DefaultCompressSize = 4 << 20
	// DefaultCompressor is the default chunk data compressor.
	DefaultCompressor = "zstd"
)
