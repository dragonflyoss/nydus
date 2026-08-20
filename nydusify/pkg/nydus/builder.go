/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"bytes"
	"cmp"
	"context"
	"io"
	"os/exec"
	"strconv"

	"github.com/pkg/errors"
)

// DefaultBuilder is the PATH-resolvable nydus binary name used when no
// explicit builder path is configured.
const DefaultBuilder = "nydus"

// DefaultLogLevel is passed to nydus subprocesses when no level is set, so
// they always receive a valid `--log-level` value.
const DefaultLogLevel = "info"

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
	// BlockGroupSize is the group uncompressed size in bytes (a multiple of 1MiB).
	BlockGroupSize uint32
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

// ExportOption describes a single `nydus export` invocation that turns a
// nydus full blob back into an OCI layer tar stream.
type ExportOption struct {
	// BuilderPath is the path (or PATH-resolvable name) of the nydus binary.
	BuilderPath string
	// BlobPath is the nydus full blob to export. Unlike the build direction it
	// must be a regular file, because the exporter memory-maps it.
	BlobPath string
	// LogLevel is the log level passed to the nydus binary (trace/debug/info/
	// warn/error). Defaults to "info" when empty.
	LogLevel string
}

// RunNydusBuild executes `nydus build` to produce a full blob at opt.BlobPath.
//
// The blob is written strictly sequentially (data -> bootstrap -> blob meta ->
// footer) which makes opt.BlobPath safe to point at a FIFO for streaming.
func RunNydusBuild(ctx context.Context, opt BuildOption) error {
	args := []string{
		"build",
		opt.SourceDir,
		"--blob", opt.BlobPath,
		"--chunk-size", strconv.FormatUint(uint64(opt.ChunkSize), 10),
		"--block-group-size", strconv.FormatUint(uint64(opt.BlockGroupSize), 10),
		"--compressor", opt.Compressor,
		"--log-level", cmp.Or(opt.LogLevel, DefaultLogLevel),
	}
	for _, excl := range opt.Excludes {
		args = append(args, "--exclude", excl)
	}

	cmd := exec.CommandContext(ctx, cmp.Or(opt.BuilderPath, DefaultBuilder), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus build: %s", stderr.String())
	}

	return nil
}

// RunNydusMerge executes `nydus merge` to overlay opt.SourcePaths into a
// single bootstrap at opt.BootstrapPath.
func RunNydusMerge(ctx context.Context, opt MergeBuildOption) error {
	args := make([]string, 0, len(opt.SourcePaths)+5)
	args = append(args, "merge")
	args = append(args, opt.SourcePaths...)
	args = append(args,
		"--bootstrap", opt.BootstrapPath,
		"--whiteout-spec", "oci",
		"--log-level", cmp.Or(opt.LogLevel, DefaultLogLevel),
	)

	cmd := exec.CommandContext(ctx, cmp.Or(opt.BuilderPath, DefaultBuilder), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus merge: %s", stderr.String())
	}
	return nil
}

// RunNydusExport executes `nydus export` to turn a nydus full blob back into
// an OCI layer, streaming the uncompressed tar into dest.
//
// A full blob carries the filesystem tree and the chunk data of exactly one
// layer, so no bootstrap, lower layer or storage backend is involved.
func RunNydusExport(ctx context.Context, opt ExportOption, dest io.Writer) error {
	args := []string{
		"export", opt.BlobPath,
		"--log-level", cmp.Or(opt.LogLevel, DefaultLogLevel),
	}

	cmd := exec.CommandContext(ctx, cmp.Or(opt.BuilderPath, DefaultBuilder), args...)
	cmd.Stdout = dest
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus export: %s", stderr.String())
	}

	return nil
}
