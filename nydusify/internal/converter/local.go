/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
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
func ConvertLocalDir(ctx context.Context, cs content.Store, opt LocalDirOption) (*ocispec.Descriptor, error) {
	if opt.Compressor == "" {
		opt.Compressor = "zstd"
	}
	if opt.ChunkSize == 0 {
		opt.ChunkSize = 1 << 20
	}
	if opt.CompressSize == 0 {
		opt.CompressSize = 1 << 20
	}

	appendFiles, err := validateAndReadAppendFiles(opt.AppendInBootstrap)
	if err != nil {
		return nil, err
	}

	buildDir, err := os.MkdirTemp(opt.WorkDir, "local-build-")
	if err != nil {
		return nil, errors.Wrap(err, "create build scratch dir")
	}
	defer func() { _ = os.RemoveAll(buildDir) }()

	// Pass the append file paths as --exclude flags to `nydus build`.
	// The Rust side resolves each path against the source directory and
	// canonicalizes it, so files outside the source are simply ignored.
	excludes := opt.AppendInBootstrap

	// Step 1: Run nydus build to produce the full blob.
	blobPath := filepath.Join(buildDir, "blob.nydus")
	if err := runNydusBuild(ctx, BuildOption{
		BuilderPath:  opt.BuilderPath,
		SourceDir:    opt.SourceDir,
		BlobPath:     blobPath,
		ChunkSize:    opt.ChunkSize,
		CompressSize: opt.CompressSize,
		Compressor:   opt.Compressor,
		LogLevel:     opt.LogLevel,
		Excludes:     excludes,
	}); err != nil {
		return nil, err
	}

	// Step 2: Ingest the blob into the content store.
	blobDesc, err := ingestBlobFile(ctx, cs, blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "ingest blob")
	}

	// Step 3: Stage blob metadata for merge and extract blob.meta.
	mergeDir, err := os.MkdirTemp(opt.WorkDir, "local-merge-")
	if err != nil {
		return nil, errors.Wrap(err, "create merge scratch dir")
	}
	defer func() { _ = os.RemoveAll(mergeDir) }()

	stagedPath, err := stageNydusMetadataFromFile(blobPath, blobDesc.Digest, mergeDir)
	if err != nil {
		return nil, errors.Wrap(err, "stage blob for merge")
	}

	blobMetaData, err := extractBlobMetaFromFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "extract blob meta")
	}
	blobMetas := []BlobMetaFile{{
		Name: blobDesc.Digest.Encoded() + ".blob.meta",
		Data: blobMetaData,
	}}

	// Step 4: Run nydus merge (single layer) to produce the bootstrap.
	bootstrapPath := filepath.Join(mergeDir, "bootstrap")
	if err := runNydusMerge(ctx, MergeBuildOption{
		BuilderPath:   opt.BuilderPath,
		SourcePaths:   []string{stagedPath},
		BootstrapPath: bootstrapPath,
		LogLevel:      opt.LogLevel,
	}); err != nil {
		return nil, err
	}

	// Step 5: Pack bootstrap layer with blob.meta and appended files.
	bootstrapData, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "read bootstrap")
	}

	bootstrapDesc, err := WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas, appendFiles)
	if err != nil {
		return nil, errors.Wrap(err, "write bootstrap layer")
	}

	// Step 6: Build OCI image config.
	config := ocispec.Image{
		Platform: platforms.DefaultSpec(),
		RootFS: ocispec.RootFS{
			Type: "layers",
			DiffIDs: []digest.Digest{
				blobDesc.Digest,
				digest.Digest(bootstrapDesc.Annotations[LayerAnnotationUncompressed]),
			},
		},
		History: []ocispec.History{
			{CreatedBy: "Nydus Build", Comment: "Nydus Data Layer"},
			{CreatedBy: "Nydus Converter", Comment: "Nydus Bootstrap Layer"},
		},
	}

	configDesc, err := writeJSON(ctx, cs, config, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		return nil, errors.Wrap(err, "write image config")
	}
	configDesc.MediaType = ocispec.MediaTypeImageConfig

	// Step 7: Build OCI manifest.
	layers := []ocispec.Descriptor{blobDesc, *bootstrapDesc}

	labels := map[string]string{
		"containerd.io/gc.ref.content.config": configDesc.Digest.String(),
	}
	for idx, l := range layers {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", idx)] = l.Digest.String()
	}

	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    *configDesc,
		Layers:    layers,
	}

	manifestDesc, err := writeJSON(ctx, cs, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, labels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}

	return manifestDesc, nil
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
