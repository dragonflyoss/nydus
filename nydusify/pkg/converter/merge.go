/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

// ReaderAt is the minimal random-access blob reader accepted by Merge. It is
// intentionally a subset of containerd's content.ReaderAt so that both
// containerd v1 and v2 content stores satisfy it.
type ReaderAt interface {
	io.ReaderAt
	Size() int64
}

// Layer is a converted nydus full blob layer to merge.
type Layer struct {
	// Digest is the full blob digest (sha256 of the entire blob artifact).
	Digest digest.Digest
	// ReaderAt provides random access to the full blob content.
	ReaderAt ReaderAt
}

// MergeOption configures a bootstrap merge (see Merge).
type MergeOption struct {
	// BuilderPath is the nydus binary path (PATH-resolvable). Defaults to "nydus".
	BuilderPath string
	// WorkDir is a scratch directory used for staging blobs and the bootstrap.
	// Defaults to os.TempDir().
	WorkDir string
	// LogLevel is the log level forwarded to `nydus merge` (trace/debug/info/
	// warn/error). Defaults to "info" when empty.
	LogLevel string
	// AppendFiles are extra files bundled into the bootstrap layer tar under
	// "image/" alongside image.boot and the blob meta artifacts.
	AppendFiles []AppendFile
}

// Merge overlays the given nydus full blob layers into a single bootstrap and
// writes the uncompressed bootstrap layer tar (`image/image.boot` plus one
// `image/<full_blob_sha256>.blob.meta` per layer) into dest. The caller is
// responsible for compressing the stream (e.g. gzip) and committing it as the
// bootstrap layer.
//
// Each layer is staged as a sparse file that materializes only the metadata
// tail (bootstrap + blob meta + footer); the data region is never read.
//
// It returns the blob digests referenced by the merged bootstrap, in layer
// order.
func Merge(ctx context.Context, layers []Layer, dest io.Writer, opt MergeOption) ([]digest.Digest, error) {
	if len(layers) == 0 {
		return nil, errors.New("no layers to merge")
	}

	mergeDir, err := os.MkdirTemp(opt.WorkDir, "nydus-merge-")
	if err != nil {
		return nil, errors.Wrap(err, "create merge scratch dir")
	}
	defer func() { _ = os.RemoveAll(mergeDir) }()

	sourcePaths := make([]string, 0, len(layers))
	blobMetas := make([]BlobMetaFile, 0, len(layers))
	blobDigests := make([]digest.Digest, 0, len(layers))
	for _, layer := range layers {
		blobPath, err := StageNydusMetadata(layer.ReaderAt, layer.ReaderAt.Size(), layer.Digest.Encoded(), mergeDir)
		if err != nil {
			return nil, errors.Wrapf(err, "stage blob %s", layer.Digest)
		}
		sourcePaths = append(sourcePaths, blobPath)

		meta, err := ExtractBlobMeta(layer.ReaderAt, layer.ReaderAt.Size())
		if err != nil {
			return nil, errors.Wrapf(err, "extract blob meta %s", layer.Digest)
		}
		blobMetas = append(blobMetas, BlobMetaFile{
			Name: layer.Digest.Encoded() + ".blob.meta",
			Data: meta,
		})
		blobDigests = append(blobDigests, layer.Digest)
	}

	bootstrapPath := filepath.Join(mergeDir, "bootstrap")
	if err := RunNydusMerge(ctx, MergeBuildOption{
		BuilderPath:   opt.BuilderPath,
		SourcePaths:   sourcePaths,
		BootstrapPath: bootstrapPath,
		LogLevel:      opt.LogLevel,
	}); err != nil {
		return nil, err
	}

	bootstrapData, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "read bootstrap")
	}

	tw := tar.NewWriter(dest)
	if err := WriteBootstrapTar(tw, bootstrapData, blobMetas, opt.AppendFiles); err != nil {
		return nil, errors.Wrap(err, "write bootstrap layer tar")
	}
	if err := tw.Close(); err != nil {
		return nil, errors.Wrap(err, "close bootstrap tar writer")
	}

	return blobDigests, nil
}
