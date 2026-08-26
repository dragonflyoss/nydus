/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"context"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Option configures a single OCI -> nydus image conversion.
type Option struct {
	// BuilderPath is the nydus binary path (PATH-resolvable). Defaults to "nydus".
	BuilderPath string
	// WorkDir is a scratch directory for layer extraction, FIFOs and staging.
	WorkDir string
	// OnBlobConverted, when set, is called once per converted layer blob as
	// soon as it is committed to the content store, so uploads can overlap
	// with the remaining conversion work. Must be safe for concurrent calls.
	OnBlobConverted func(desc ocispec.Descriptor)
	// ChunkSize is the nydus file chunk size in bytes.
	ChunkSize uint32
	// BlockGroupSize is the nydus block group uncompressed size in bytes (a multiple of
	// 1MiB). Controls the uncompressed size of each blob meta block group.
	BlockGroupSize uint32
	// Compressor is the chunk data compressor ("none" or "zstd").
	Compressor string
	// LogLevel is the log level forwarded to the `nydus` subprocesses
	// (trace/debug/info/warn/error). Defaults to "info" when empty.
	LogLevel string
	// PlatformMC selects which platforms to convert. Defaults to all.
	PlatformMC platforms.MatchComparer
}

// Convert converts the image rooted at srcDesc (already present in cs) into a
// nydus image and returns the new root descriptor. The converted content is
// written back into cs.
func Convert(ctx context.Context, cs content.Store, srcDesc ocispec.Descriptor, opt Option) (*ocispec.Descriptor, error) {
	if opt.Compressor == "" {
		opt.Compressor = nydus.DefaultCompressor
	}
	if opt.ChunkSize == 0 {
		opt.ChunkSize = nydus.DefaultChunkSize
	}
	if opt.BlockGroupSize == 0 {
		opt.BlockGroupSize = nydus.DefaultBlockGroupSize
	}
	platformMC := opt.PlatformMC
	if platformMC == nil {
		platformMC = platforms.All
	}

	layerFn := LayerConvertFunc(nydus.PackOption{
		BuilderPath:    opt.BuilderPath,
		WorkDir:        opt.WorkDir,
		ChunkSize:      opt.ChunkSize,
		BlockGroupSize: opt.BlockGroupSize,
		Compressor:     opt.Compressor,
		LogLevel:       opt.LogLevel,
	})
	if opt.OnBlobConverted != nil {
		inner := layerFn
		layerFn = func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
			newDesc, err := inner(ctx, cs, desc)
			if err == nil && newDesc != nil && nydus.IsBlob(*newDesc) {
				opt.OnBlobConverted(*newDesc)
			}
			return newDesc, err
		}
	}
	hookFn := ConvertHookFunc(nydus.MergeOption{
		BuilderPath: opt.BuilderPath,
		WorkDir:     opt.WorkDir,
		LogLevel:    opt.LogLevel,
	})

	indexConvertFn := converter.IndexConvertFuncWithHook(
		layerFn,
		true, // docker2oci: normalize docker media types to OCI
		platformMC,
		converter.ConvertHooks{PostConvertHook: hookFn},
	)

	// A source that is already (partly) a nydus image carries blob layers
	// whose diff ids cannot be computed by decompression; label them upfront
	// so images.GetDiffID takes the fast path.
	if err := labelNydusBlobDiffIDs(ctx, cs, srcDesc, platformMC); err != nil {
		return nil, errors.Wrap(err, "label nydus blob diff ids")
	}
	// Label every source OCI layer with its diff id from the image config:
	// the converter calls images.GetDiffID per layer BEFORE spawning the
	// parallel layer conversions, and without the label that decompresses
	// every gzip layer serially — for a large image several seconds on the
	// critical path for digests the config already carries.
	if err := labelSourceLayerDiffIDs(ctx, cs, srcDesc, platformMC); err != nil {
		return nil, errors.Wrap(err, "label source layer diff ids")
	}

	newDesc, err := indexConvertFn(ctx, cs, srcDesc)
	if err != nil {
		return nil, errors.Wrap(err, "convert image")
	}
	if newDesc == nil {
		// Nothing was modified (e.g. the source is already a nydus image);
		// the source descriptor is the conversion result.
		return &srcDesc, nil
	}
	return newDesc, nil
}
