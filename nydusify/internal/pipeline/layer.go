/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// LayerConvertFunc returns a converter.ConvertFunc that converts a single OCI
// image layer into a nydus data blob layer.
//
// The OCI layer is decompressed and extracted into a scratch directory
// (preserving OCI whiteouts), then `nydus build` streams the resulting full
// blob through a FIFO directly into the content store.
func LayerConvertFunc(opt nydus.PackOption) converter.ConvertFunc {
	// The containerd converter spawns every layer conversion at once; each
	// one runs an extraction plus a `nydus build`, so an unbounded fan-out
	// multiplies peak memory and thrashes the CPU on many-layer images.
	slots := make(chan struct{}, layerConvertConcurrency())
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !images.IsLayerType(desc.MediaType) {
			return nil, nil
		}
		// Skip layers that are already in nydus format.
		if nydus.IsBlob(desc) || nydus.IsBootstrap(desc) {
			return nil, nil
		}

		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		newDesc, err := convertLayer(ctx, cs, desc, opt)
		if err != nil {
			return nil, errors.Wrapf(err, "convert layer %s", desc.Digest)
		}
		return newDesc, nil
	}
}

// layerConvertConcurrency bounds parallel layer conversions: enough to keep
// the cores busy, small enough to bound the sum of concurrent extract dirs
// and builder RSS. NYDUSIFY_LAYER_CONCURRENCY overrides the default (large
// layers dominate the critical path, so lowering it trades little wall time
// for a proportional peak-memory cut).
func layerConvertConcurrency() int {
	if env := os.Getenv("NYDUSIFY_LAYER_CONCURRENCY"); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			return n
		}
	}
	n := runtime.NumCPU() / 2
	if n < 2 {
		n = 2
	}
	if n > 4 {
		n = 4
	}
	return n
}

func convertLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt nydus.PackOption) (*ocispec.Descriptor, error) {
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
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    blobDigest,
		Size:      blobSize,
		Annotations: map[string]string{
			// A nydus full blob is self-describing and uncompressed at the
			// layer level, so the diff id equals the blob digest.
			nydus.LayerAnnotationUncompressed: blobDigest.String(),
			nydus.LayerAnnotationNydusBlob:    "true",
		},
	}, nil
}

// extractOCILayer reads an OCI layer blob from the content store, decompresses
// it (gzip/zstd/uncompressed are auto-detected) and extracts it into dir.
func extractOCILayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, dir string) error {
	decompressed, err := oci.OpenDecompressedBlob(ctx, cs, desc)
	if err != nil {
		return errors.Wrap(err, "open layer")
	}
	defer func() { _ = decompressed.Close() }()

	if err := nydus.ExtractTar(ctx, decompressed, dir); err != nil {
		return errors.Wrap(err, "extract layer tar")
	}
	return nil
}

// buildBlobToStore runs `nydus build` via pkg/nydus, streaming the full
// blob straight into the content store, and returns the committed blob digest
// and size.
func buildBlobToStore(ctx context.Context, cs content.Store, srcRef, sourceDir string, opt nydus.PackOption) (digest.Digest, int64, error) {
	// Record the uncompressed digest as a content-store label so that
	// containerd's images.GetDiffID takes the fast path instead of trying to
	// decompress the blob. A nydus full blob is uncompressed at the layer
	// level, so its diff id equals the blob digest.
	return oci.CommitBlob(ctx, cs, "nydus-build-"+srcRef, "",
		func(dgst digest.Digest) map[string]string {
			return map[string]string{nydus.LayerAnnotationUncompressed: dgst.String()}
		},
		func(w io.Writer) error {
			return errors.Wrap(nydus.BuildBlob(ctx, w, sourceDir, opt), "build nydus blob")
		},
	)
}
