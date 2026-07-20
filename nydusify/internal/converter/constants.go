/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"io"

	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"
)

// Media types, annotations and conversion primitives are re-exported from the
// public pkg/converter package so internal packages (checker, remote, main)
// keep their existing import surface.
const (
	// ManifestOSFeatureNydus marks a platform manifest in an image index as a
	// remote (lazy-loadable) nydus image.
	ManifestOSFeatureNydus = pkgconv.ManifestOSFeatureNydus

	// MediaTypeNydusBlob is the media type of a single converted data layer
	// (a nydus full blob: data + bootstrap + blob meta + footer).
	MediaTypeNydusBlob = pkgconv.MediaTypeNydusBlob

	// BootstrapFileNameInLayer is the path of the bootstrap entry inside the
	// gzip-compressed bootstrap layer tarball.
	BootstrapFileNameInLayer = pkgconv.BootstrapFileNameInLayer

	// BlobMetaDirInLayer is the directory inside the bootstrap layer tarball
	// that holds the per-layer `<full_blob_sha256>.blob.meta` artifacts, packed
	// alongside image.boot.
	BlobMetaDirInLayer = pkgconv.BlobMetaDirInLayer

	// LayerAnnotationNydusBlob marks a layer as a nydus data blob.
	LayerAnnotationNydusBlob = pkgconv.LayerAnnotationNydusBlob
	// LayerAnnotationNydusBootstrap marks a layer as the nydus bootstrap.
	LayerAnnotationNydusBootstrap = pkgconv.LayerAnnotationNydusBootstrap
	// LayerAnnotationNydusFsVersion marks a bootstrap layer as a nydus pmem
	// image for snapshotters that dispatch by nydus fs-version annotations.
	LayerAnnotationNydusFsVersion = pkgconv.LayerAnnotationNydusFsVersion
	// NydusFsVersion is the pseudo nydus fs-version used for nydus pmem images.
	NydusFsVersion = pkgconv.NydusFsVersion

	// LayerAnnotationUncompressed holds the uncompressed digest (diff id) of a
	// layer, following the containerd convention.
	LayerAnnotationUncompressed = pkgconv.LayerAnnotationUncompressed
)

// Types re-exported from pkg/converter.
type (
	// BuildOption describes a single `nydus build` invocation.
	BuildOption = pkgconv.BuildOption
	// MergeBuildOption describes a single `nydus merge` invocation.
	MergeBuildOption = pkgconv.MergeBuildOption
	// BlobMetaFile is a per-layer blob meta artifact packed into the bootstrap
	// layer alongside image.boot, named "<full_blob_sha256>.blob.meta".
	BlobMetaFile = pkgconv.BlobMetaFile
	// AppendFile describes a file to bundle into the bootstrap layer tar
	// alongside image.boot and the blob meta artifacts.
	AppendFile = pkgconv.AppendFile
	// PackOption configures per-layer conversion.
	PackOption = pkgconv.PackOption
	// MergeOption configures the bootstrap merge / manifest rewrite step.
	MergeOption = pkgconv.MergeOption
)

func runNydusBuild(ctx context.Context, opt BuildOption) error {
	return pkgconv.RunNydusBuild(ctx, opt)
}

func runNydusMerge(ctx context.Context, opt MergeBuildOption) error {
	return pkgconv.RunNydusMerge(ctx, opt)
}

func extractTar(ctx context.Context, r io.Reader, dir string) error {
	return pkgconv.ExtractTar(ctx, r, dir)
}
