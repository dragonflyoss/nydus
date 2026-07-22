/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

const maxAppendFileSize = 512 << 20 // 512 MiB

// LocalDirOption configures a local directory -> nydus image conversion.
type LocalDirOption struct {
	BuilderPath       string
	WorkDir           string
	ChunkSize         uint32
	CompressSize      uint32
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
		CompressSize:      opt.CompressSize,
		Compressor:        opt.Compressor,
		LogLevel:          opt.LogLevel,
		Platform:          platforms.DefaultSpec(),
		Sources:           []Source{{Dir: opt.SourceDir}},
		AppendInBootstrap: opt.AppendInBootstrap,
	})
}

// validateAndReadAppendFiles validates the list of file paths and reads their
// contents, returning them ready for embedding in the bootstrap tar.
// It returns two parallel slices: the AppendFile entries (with basename and
// data) and the original absolute paths (used by the caller to compute
// exclusions from the source directory).
func validateAndReadAppendFiles(paths []string) ([]AppendFile, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool, len(paths))
	result := make([]AppendFile, 0, len(paths))

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, errors.Wrapf(err, "append-in-bootstrap file %q", p)
		}
		if info.IsDir() {
			return nil, errors.Errorf("append-in-bootstrap path %q is a directory, not a file", p)
		}
		if info.Size() > maxAppendFileSize {
			return nil, errors.Errorf("append-in-bootstrap file %q is too large (%d bytes, max %d)", p, info.Size(), maxAppendFileSize)
		}

		name := filepath.Base(p)
		if name == "image.boot" || strings.HasSuffix(name, ".blob.meta") {
			return nil, errors.Errorf("append-in-bootstrap file basename %q conflicts with reserved bootstrap entry", name)
		}
		if seen[name] {
			return nil, errors.Errorf("append-in-bootstrap duplicate basename %q", name)
		}
		seen[name] = true

		data, err := os.ReadFile(p)
		if err != nil {
			return nil, errors.Wrapf(err, "read append-in-bootstrap file %q", p)
		}
		result = append(result, AppendFile{Name: name, Data: data})
	}
	return result, nil
}

// ingestBlobFile hashes a blob file and copies it into the content store,
// returning its descriptor.
func ingestBlobFile(ctx context.Context, cs content.Store, path string) (ocispec.Descriptor, error) {
	f, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "open blob file")
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "stat blob file")
	}
	size := info.Size()

	digester := digest.SHA256.Digester()
	if _, err := io.Copy(digester.Hash(), f); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "hash blob file")
	}
	dgst := digester.Digest()

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "seek blob file")
	}

	cw, err := content.OpenWriter(ctx, cs, content.WithRef("nydus-local-blob-"+dgst.String()))
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "open content writer")
	}
	defer func() { _ = cw.Close() }()

	if err := content.Copy(ctx, cw, f, size, dgst, content.WithLabels(map[string]string{
		LayerAnnotationUncompressed: dgst.String(),
	})); err != nil && !errdefs.IsAlreadyExists(err) {
		return ocispec.Descriptor{}, errors.Wrap(err, "commit blob to content store")
	}

	return ocispec.Descriptor{
		MediaType: MediaTypeNydusBlob,
		Digest:    dgst,
		Size:      size,
		Annotations: map[string]string{
			LayerAnnotationUncompressed: dgst.String(),
			LayerAnnotationNydusBlob:    "true",
		},
	}, nil
}

// stageNydusMetadataFromFile is like stageNydusMetadata but reads from a
// local file instead of the content store.
func stageNydusMetadataFromFile(blobPath string, blobDigest digest.Digest, dir string) (string, error) {
	f, err := os.Open(blobPath)
	if err != nil {
		return "", errors.Wrap(err, "open blob file")
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", errors.Wrap(err, "stat blob file")
	}

	return pkgconv.StageNydusMetadata(f, info.Size(), blobDigest.Encoded(), dir)
}

// extractBlobMetaFromFile reads the blob meta region from a local blob file.
func extractBlobMetaFromFile(blobPath string) ([]byte, error) {
	f, err := os.Open(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "open blob file")
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "stat blob file")
	}

	return pkgconv.ExtractBlobMeta(f, info.Size())
}
