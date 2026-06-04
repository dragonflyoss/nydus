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
	// Compressor is the chunk data compressor ("none" or "zstd").
	Compressor string
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
	platformMC := opt.PlatformMC
	if platformMC == nil {
		platformMC = platforms.All
	}

	layerFn := LayerConvertFunc(PackOption{
		BuilderPath: opt.BuilderPath,
		WorkDir:     opt.WorkDir,
		ChunkSize:   opt.ChunkSize,
		Compressor:  opt.Compressor,
	})
	hookFn := ConvertHookFunc(MergeOption{
		BuilderPath: opt.BuilderPath,
		WorkDir:     opt.WorkDir,
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
		return nil, errors.New("conversion produced no result")
	}
	return newDesc, nil
}
