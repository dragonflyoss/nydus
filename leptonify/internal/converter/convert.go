/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Option configures a single OCI -> lepton image conversion.
type Option struct {
	// BuilderPath is the lepton binary path (PATH-resolvable). Defaults to "lepton".
	BuilderPath string
	// WorkDir is a scratch directory for layer extraction, FIFOs and staging.
	WorkDir string
	// ChunkSize is the lepton file chunk size in bytes.
	ChunkSize uint32
	// CompressSize is the lepton group uncompressed size in bytes (a multiple of
	// 1MiB). Controls the uncompressed size of each blob meta group.
	CompressSize uint32
	// Compressor is the chunk data compressor ("none" or "zstd").
	Compressor string
	// LogLevel is the log level forwarded to the `lepton` subprocesses
	// (trace/debug/info/warn/error). Defaults to "info" when empty.
	LogLevel string
	// PlatformMC selects which platforms to convert. Defaults to all.
	PlatformMC platforms.MatchComparer
}

// Convert converts the image rooted at srcDesc (already present in cs) into a
// lepton image and returns the new root descriptor. The converted content is
// written back into cs.
func Convert(ctx context.Context, cs content.Store, srcDesc ocispec.Descriptor, opt Option) (*ocispec.Descriptor, error) {
	if opt.Compressor == "" {
		opt.Compressor = "zstd"
	}
	if opt.ChunkSize == 0 {
		opt.ChunkSize = 1 << 20
	}
	if opt.CompressSize == 0 {
		opt.CompressSize = 4 << 20
	}
	platformMC := opt.PlatformMC
	if platformMC == nil {
		platformMC = platforms.All
	}

	layerFn := LayerConvertFunc(PackOption{
		BuilderPath:  opt.BuilderPath,
		WorkDir:      opt.WorkDir,
		ChunkSize:    opt.ChunkSize,
		CompressSize: opt.CompressSize,
		Compressor:   opt.Compressor,
		LogLevel:     opt.LogLevel,
	})
	hookFn := ConvertHookFunc(MergeOption{
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

	newDesc, err := indexConvertFn(ctx, cs, srcDesc)
	if err != nil {
		return nil, errors.Wrap(err, "convert image")
	}
	if newDesc == nil {
		// Nothing was modified (e.g. the source is already a lepton image);
		// the source descriptor is the conversion result.
		return &srcDesc, nil
	}
	return newDesc, nil
}
