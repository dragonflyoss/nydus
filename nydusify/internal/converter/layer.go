/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/errdefs"
	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
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

// LayerConvertFunc returns a converter.ConvertFunc that converts a single OCI
// image layer into a nydus data blob layer.
//
// The OCI layer is decompressed and extracted into a scratch directory
// (preserving OCI whiteouts), then `nydus build` streams the resulting full
// blob through a FIFO directly into the content store.
func LayerConvertFunc(opt PackOption) converter.ConvertFunc {
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !images.IsLayerType(desc.MediaType) {
			return nil, nil
		}
		// Skip layers that are already in nydus format.
		if IsNydusBlob(desc) || IsNydusBootstrap(desc) {
			return nil, nil
		}

		newDesc, err := convertLayer(ctx, cs, desc, opt)
		if err != nil {
			return nil, errors.Wrapf(err, "convert layer %s", desc.Digest)
		}
		return newDesc, nil
	}
}

func convertLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt PackOption) (*ocispec.Descriptor, error) {
	// Prepare a unique scratch area for this layer.
	layerDir, err := os.MkdirTemp(opt.WorkDir, "layer-")
	if err != nil {
		return nil, errors.Wrap(err, "create scratch dir")
	}
	defer func() { _ = os.RemoveAll(layerDir) }()

	sourceDir := filepath.Join(layerDir, "rootfs")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return nil, errors.Wrap(err, "create rootfs dir")
	}

	// Decompress and extract the OCI layer into sourceDir, preserving whiteouts.
	if err := extractOCILayer(ctx, cs, desc, sourceDir); err != nil {
		return nil, err
	}

	// Stream `nydus build` output through a FIFO into the content store.
	blobDigest, blobSize, err := buildBlobToStore(ctx, cs, desc.Digest.String(), sourceDir, opt)
	if err != nil {
		return nil, err
	}

	return &ocispec.Descriptor{
		MediaType: MediaTypeNydusBlob,
		Digest:    blobDigest,
		Size:      blobSize,
		Annotations: map[string]string{
			// A nydus full blob is self-describing and uncompressed at the
			// layer level, so the diff id equals the blob digest.
			LayerAnnotationUncompressed: blobDigest.String(),
			LayerAnnotationNydusBlob:    "true",
		},
	}, nil
}

// extractOCILayer reads an OCI layer blob from the content store, decompresses
// it (gzip/zstd/uncompressed are auto-detected) and extracts it into dir.
func extractOCILayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, dir string) error {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "open layer reader")
	}
	defer func() { _ = ra.Close() }()

	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		return errors.Wrap(err, "decompress layer")
	}
	defer func() { _ = decompressed.Close() }()

	if err := extractTar(ctx, decompressed, dir); err != nil {
		return errors.Wrap(err, "extract layer tar")
	}
	return nil
}

// buildBlobToStore runs `nydus build` via pkg/converter, streaming the full
// blob straight into the content store, and returns the committed blob digest
// and size.
func buildBlobToStore(ctx context.Context, cs content.Store, srcRef, sourceDir string, opt PackOption) (digest.Digest, int64, error) {
	cw, err := content.OpenWriter(ctx, cs, content.WithRef("nydus-build-"+srcRef))
	if err != nil {
		return "", 0, errors.Wrap(err, "open content writer")
	}
	defer func() { _ = cw.Close() }()

	if err := pkgconv.BuildBlob(ctx, cw, sourceDir, opt); err != nil {
		return "", 0, errors.Wrap(err, "build nydus blob")
	}

	// Record the uncompressed digest as a content-store label so that
	// containerd's images.GetDiffID takes the fast path instead of trying to
	// decompress the blob. A nydus full blob is uncompressed at the layer
	// level, so its diff id equals the blob digest.
	dgst := cw.Digest()
	if err := cw.Commit(ctx, 0, "", content.WithLabels(map[string]string{
		LayerAnnotationUncompressed: dgst.String(),
	})); err != nil && !errdefs.IsAlreadyExists(err) {
		return "", 0, errors.Wrap(err, "commit blob")
	}

	info, err := cs.Info(ctx, dgst)
	if err != nil {
		return "", 0, errors.Wrap(err, "stat committed blob")
	}
	return dgst, info.Size, nil
}
