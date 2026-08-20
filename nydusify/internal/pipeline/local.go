/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// LocalDirOption configures a local directory -> nydus image conversion.
type LocalDirOption struct {
	BuilderPath       string
	WorkDir           string
	ChunkSize         uint32
	BlockGroupSize    uint32
	Compressor        string
	LogLevel          string
	SourceDir         string
	AppendInBootstrap []string
}

// ConvertLocalDir converts a local directory into a single-layer nydus image
// and returns the root manifest descriptor. The converted content is written
// into cs, ready for pushing to a registry.
//
// Files specified in AppendInBootstrap are bundled into the bootstrap layer tar
// (as entries under "image/"). If any of those files reside inside SourceDir,
// they are passed as --exclude flags to `nydus build` so their data does not
// also end up in the blob data region.
//
// It is a thin wrapper around ConvertMultiSource with a single directory
// source.
func ConvertLocalDir(ctx context.Context, cs content.Store, opt LocalDirOption) (*ocispec.Descriptor, error) {
	return ConvertMultiSource(ctx, cs, MultiSourceOption{
		BuilderPath:       opt.BuilderPath,
		WorkDir:           opt.WorkDir,
		ChunkSize:         opt.ChunkSize,
		BlockGroupSize:    opt.BlockGroupSize,
		Compressor:        opt.Compressor,
		LogLevel:          opt.LogLevel,
		Platform:          platforms.DefaultSpec(),
		Sources:           []Source{{Dir: opt.SourceDir}},
		AppendInBootstrap: opt.AppendInBootstrap,
	})
}
