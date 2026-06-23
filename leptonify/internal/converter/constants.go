/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

// Media types and annotations used by lepton images.
//
// The on-wire manifest format intentionally mirrors the nydus image format so
// that existing snapshotters and tooling that already understand the nydus
// layout can consume lepton images with minimal changes.
const (
	// ManifestOSFeatureLepton marks a platform manifest in an image index as a
	// remote (lazy-loadable) lepton image.
	ManifestOSFeatureLepton = "nydus.remoteimage.v1"

	// MediaTypeLeptonBlob is the media type of a single converted data layer
	// (a lepton full blob: data + bootstrap + blob meta + footer).
	MediaTypeLeptonBlob = "application/vnd.oci.image.layer.nydus.blob.v1"

	// BootstrapFileNameInLayer is the path of the bootstrap entry inside the
	// gzip-compressed bootstrap layer tarball.
	BootstrapFileNameInLayer = "image/image.boot"

	// BlobMetaDirInLayer is the directory inside the bootstrap layer tarball
	// that holds the per-layer `<full_blob_sha256>.blob.meta` artifacts, packed
	// alongside image.boot.
	BlobMetaDirInLayer = "image"

	// LayerAnnotationLeptonBlob marks a layer as a lepton data blob.
	LayerAnnotationLeptonBlob = "containerd.io/snapshot/nydus-blob"
	// LayerAnnotationLeptonBootstrap marks a layer as the lepton bootstrap.
	LayerAnnotationLeptonBootstrap = "containerd.io/snapshot/nydus-bootstrap"
	// LayerAnnotationLeptonFsVersion marks a bootstrap layer as a lepton pmem
	// image for snapshotters that dispatch by nydus fs-version annotations.
	LayerAnnotationLeptonFsVersion = "containerd.io/snapshot/nydus-fs-version"
	// LeptonFsVersion is the pseudo nydus fs-version used for lepton pmem images.
	LeptonFsVersion = "7"

	// LayerAnnotationUncompressed holds the uncompressed digest (diff id) of a
	// layer, following the containerd convention.
	LayerAnnotationUncompressed = "containerd.io/uncompressed"
)
