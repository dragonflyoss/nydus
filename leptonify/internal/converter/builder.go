/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package converter converts OCI image layers into lepton blobs and bootstraps.
package converter

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"

	"github.com/pkg/errors"
)

// BuildOption describes a single `lepton build` invocation that converts a
// directory tree into a lepton full blob.
type BuildOption struct {
	// BuilderPath is the path (or PATH-resolvable name) of the lepton binary.
	BuilderPath string
	// SourceDir is the directory tree to build the layer from.
	SourceDir string
	// BlobPath is the output blob path. It may be a FIFO so the blob can be
	// streamed directly into a content store without staging on disk.
	BlobPath string
	// ChunkSize is the file chunk size in bytes.
	ChunkSize uint32
	// Compressor is the chunk data compression algorithm ("none" or "zstd").
	Compressor string
}

// MergeBuildOption describes a single `lepton merge` invocation that overlays a
// set of lepton blobs into a single bootstrap.
type MergeBuildOption struct {
	// BuilderPath is the path (or PATH-resolvable name) of the lepton binary.
	BuilderPath string
	// SourcePaths are the lepton blob files to merge. Each file MUST be named by
	// the lowercase hex sha256 of its content (the lepton merge subcommand
	// validates this).
	SourcePaths []string
	// BootstrapPath is the output bootstrap path.
	BootstrapPath string
}

func builderBinary(path string) string {
	if path == "" {
		return "lepton"
	}
	return path
}

// runLeptonBuild executes `lepton build` to produce a full blob at opt.BlobPath.
//
// The blob is written strictly sequentially (data -> bootstrap -> blob meta ->
// footer) which makes opt.BlobPath safe to point at a FIFO for streaming.
func runLeptonBuild(ctx context.Context, opt BuildOption) error {
	args := []string{
		"build",
		opt.SourceDir,
		"--blob", opt.BlobPath,
		"--chunk-size", strconv.FormatUint(uint64(opt.ChunkSize), 10),
		"--compressor", opt.Compressor,
		"--log-level", "warn",
	}

	cmd := exec.CommandContext(ctx, builderBinary(opt.BuilderPath), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "lepton build failed: %s", stderr.String())
	}
	return nil
}

// runLeptonMerge executes `lepton merge` to overlay opt.SourcePaths into a
// single bootstrap at opt.BootstrapPath.
func runLeptonMerge(ctx context.Context, opt MergeBuildOption) error {
	args := make([]string, 0, len(opt.SourcePaths)+5)
	args = append(args, "merge")
	args = append(args, opt.SourcePaths...)
	args = append(args,
		"--bootstrap", opt.BootstrapPath,
		"--whiteout-spec", "oci",
		"--log-level", "warn",
	)

	cmd := exec.CommandContext(ctx, builderBinary(opt.BuilderPath), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "lepton merge failed: %s", stderr.String())
	}
	return nil
}
