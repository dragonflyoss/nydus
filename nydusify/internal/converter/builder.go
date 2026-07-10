/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package converter converts OCI image layers into nydus blobs and bootstraps.
package converter

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"

	"github.com/pkg/errors"
)

// BuildOption describes a single `nydus build` invocation that converts a
// directory tree into a nydus full blob.
type BuildOption struct {
	// BuilderPath is the path (or PATH-resolvable name) of the nydus binary.
	BuilderPath string
	// SourceDir is the directory tree to build the layer from.
	SourceDir string
	// BlobPath is the output blob path. It may be a FIFO so the blob can be
	// streamed directly into a content store without staging on disk.
	BlobPath string
	// ChunkSize is the file chunk size in bytes.
	ChunkSize uint32
	// CompressSize is the group uncompressed size in bytes (a multiple of 1MiB).
	CompressSize uint32
	// Compressor is the chunk data compression algorithm ("none" or "zstd").
	Compressor string
	// LogLevel is the log level passed to `nydus build` (trace/debug/info/warn/
	// error). Defaults to "info" when empty.
	LogLevel string
	// Excludes is the list of relative paths to exclude from the build. Each
	// path is passed as a --exclude flag to `nydus build`.
	Excludes []string
}

// MergeBuildOption describes a single `nydus merge` invocation that overlays a
// set of nydus blobs into a single bootstrap.
type MergeBuildOption struct {
	// BuilderPath is the path (or PATH-resolvable name) of the nydus binary.
	BuilderPath string
	// SourcePaths are the nydus blob files to merge. Each file MUST be named by
	// the lowercase hex sha256 of its content (the nydus merge subcommand
	// validates this).
	SourcePaths []string
	// BootstrapPath is the output bootstrap path.
	BootstrapPath string
	// LogLevel is the log level passed to `nydus merge` (trace/debug/info/warn/
	// error). Defaults to "info" when empty.
	LogLevel string
}

func builderBinary(path string) string {
	if path == "" {
		return "nydus"
	}
	return path
}

// nydusLogLevel returns level, or "info" when level is empty, so a nydus
// subprocess always receives a valid `--log-level` value.
func nydusLogLevel(level string) string {
	if level == "" {
		return "info"
	}
	return level
}

// runNydusBuild executes `nydus build` to produce a full blob at opt.BlobPath.
//
// The blob is written strictly sequentially (data -> bootstrap -> blob meta ->
// footer) which makes opt.BlobPath safe to point at a FIFO for streaming.
func runNydusBuild(ctx context.Context, opt BuildOption) error {
	args := []string{
		"build",
		opt.SourceDir,
		"--blob", opt.BlobPath,
		"--chunk-size", strconv.FormatUint(uint64(opt.ChunkSize), 10),
		"--compress-size", strconv.FormatUint(uint64(opt.CompressSize), 10),
		"--compressor", opt.Compressor,
		"--log-level", nydusLogLevel(opt.LogLevel),
	}
	for _, excl := range opt.Excludes {
		args = append(args, "--exclude", excl)
	}

	cmd := exec.CommandContext(ctx, builderBinary(opt.BuilderPath), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus build failed: %s", stderr.String())
	}
	return nil
}

// runNydusMerge executes `nydus merge` to overlay opt.SourcePaths into a
// single bootstrap at opt.BootstrapPath.
func runNydusMerge(ctx context.Context, opt MergeBuildOption) error {
	args := make([]string, 0, len(opt.SourcePaths)+5)
	args = append(args, "merge")
	args = append(args, opt.SourcePaths...)
	args = append(args,
		"--bootstrap", opt.BootstrapPath,
		"--whiteout-spec", "oci",
		"--log-level", nydusLogLevel(opt.LogLevel),
	)

	cmd := exec.CommandContext(ctx, builderBinary(opt.BuilderPath), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus merge failed: %s", stderr.String())
	}
	return nil
}
