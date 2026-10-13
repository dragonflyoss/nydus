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
// The decompressed OCI tar streams through the builder into the content store.
func LayerConvertFunc(opt nydus.PackOption) converter.ConvertFunc {
	// The containerd converter spawns every layer conversion at once; each
	// one runs a tar stream plus a `nydus build`, so an unbounded fan-out
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
// the cores busy, small enough to bound concurrent builder RSS.
// NYDUSIFY_LAYER_CONCURRENCY overrides the default (large
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
	blobDigest, blobSize, err := oci.CommitBlob(ctx, cs, "nydus-build-"+desc.Digest.String(), "",
		func(dgst digest.Digest) map[string]string {
			return map[string]string{nydus.LayerAnnotationUncompressed: dgst.String()}
		},
		func(dest io.Writer) error {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			input, err := oci.OpenDecompressedBlob(ctx, cs, desc)
			if err != nil {
				return err
			}
			defer func() { _ = input.Close() }()
			writer, err := nydus.Pack(ctx, dest, opt)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(writer, input)
			if copyErr != nil {
				cancel()
			}
			closeErr := writer.Close()
			if copyErr != nil {
				return errors.Wrap(copyErr, "stream OCI layer tar")
			}
			return closeErr
		},
	)
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
