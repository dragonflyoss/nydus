/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// MergeOption configures the bootstrap merge / manifest rewrite step.
type MergeOption struct {
	// BuilderPath is the lepton binary path (PATH-resolvable). Defaults to "lepton".
	BuilderPath string
	// WorkDir is a scratch directory used for staging blobs and the bootstrap.
	WorkDir string
}

// ConvertHookFunc returns a converter.ConvertHookFunc invoked after each blob
// is converted. It hooks index and manifest conversion to merge the per-layer
// lepton blobs into a single bootstrap layer.
func ConvertHookFunc(opt MergeOption) converter.ConvertHookFunc {
	return func(ctx context.Context, cs content.Store, orgDesc ocispec.Descriptor, newDesc *ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if newDesc == nil {
			return &orgDesc, nil
		}
		switch {
		case images.IsIndexType(newDesc.MediaType):
			return convertIndex(ctx, cs, newDesc)
		case images.IsManifestType(newDesc.MediaType):
			return convertManifest(ctx, cs, newDesc, opt)
		default:
			return newDesc, nil
		}
	}
}

// convertIndex collapses a converted manifest list to a single manifest when it
// contains only one entry, mirroring the nydus behavior.
func convertIndex(ctx context.Context, cs content.Store, newDesc *ocispec.Descriptor) (*ocispec.Descriptor, error) {
	var index ocispec.Index
	if _, err := readJSON(ctx, cs, &index, *newDesc); err != nil {
		return nil, errors.Wrap(err, "read index json")
	}
	if len(index.Manifests) == 1 {
		return &index.Manifests[0], nil
	}
	return newDesc, nil
}

// convertManifest merges all lepton blob layers in the manifest into a single
// lepton bootstrap layer, rewrites the image config, and rewrites the manifest.
func convertManifest(ctx context.Context, cs content.Store, newDesc *ocispec.Descriptor, opt MergeOption) (*ocispec.Descriptor, error) {
	var manifest ocispec.Manifest
	manifestLabels, err := readJSON(ctx, cs, &manifest, *newDesc)
	if err != nil {
		return nil, errors.Wrap(err, "read manifest json")
	}

	// Merge the lepton blob layers into a bootstrap layer.
	bootstrapDesc, err := mergeLayers(ctx, cs, manifest.Layers, opt)
	if err != nil {
		return nil, errors.Wrap(err, "merge lepton layers")
	}

	// The final layer list is all data blobs followed by the bootstrap.
	layers := make([]ocispec.Descriptor, 0, len(manifest.Layers)+1)
	layers = append(layers, manifest.Layers...)
	layers = append(layers, *bootstrapDesc)

	// Rewrite gc labels so referenced content is retained.
	for idx, l := range layers {
		manifestLabels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", idx)] = l.Digest.String()
	}

	// Rewrite the image config: diff ids and history.
	var config ocispec.Image
	configLabels, err := readJSON(ctx, cs, &config, manifest.Config)
	if err != nil {
		return nil, errors.Wrap(err, "read image config")
	}
	diffIDs := make([]digest.Digest, 0, len(layers))
	for _, l := range layers {
		if uncompressed := l.Annotations[LayerAnnotationUncompressed]; uncompressed != "" {
			diffIDs = append(diffIDs, digest.Digest(uncompressed))
		}
	}
	config.RootFS.DiffIDs = diffIDs
	config.History = append(config.History, ocispec.History{
		CreatedBy: "Lepton Converter",
		Comment:   "Lepton Bootstrap Layer",
	})

	newConfigDesc, err := writeJSON(ctx, cs, config, manifest.Config, configLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write image config")
	}
	newConfigDesc.MediaType = ocispec.MediaTypeImageConfig
	manifest.Config = *newConfigDesc
	manifest.Layers = layers
	manifestLabels["containerd.io/gc.ref.content.config"] = newConfigDesc.Digest.String()

	newManifestDesc, err := writeJSON(ctx, cs, manifest, *newDesc, manifestLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	// Preserve the platform metadata from the input manifest descriptor.
	newManifestDesc.Platform = newDesc.Platform
	return newManifestDesc, nil
}

// mergeLayers stages each lepton blob to the work dir (named by its content
// digest, as required by `lepton merge`), runs the merge, and packs the
// resulting bootstrap into a gzip-compressed layer committed to the store.
func mergeLayers(ctx context.Context, cs content.Store, descs []ocispec.Descriptor, opt MergeOption) (*ocispec.Descriptor, error) {
	mergeDir, err := os.MkdirTemp(opt.WorkDir, "merge-")
	if err != nil {
		return nil, errors.Wrap(err, "create merge scratch dir")
	}
	defer func() { _ = os.RemoveAll(mergeDir) }()

	sourcePaths := make([]string, 0, len(descs))
	for _, desc := range descs {
		blobPath, err := stageLeptonMetadata(ctx, cs, desc, mergeDir)
		if err != nil {
			return nil, errors.Wrapf(err, "stage blob %s", desc.Digest)
		}
		sourcePaths = append(sourcePaths, blobPath)
	}

	bootstrapPath := filepath.Join(mergeDir, "bootstrap")
	if err := runLeptonMerge(ctx, MergeBuildOption{
		BuilderPath:   opt.BuilderPath,
		SourcePaths:   sourcePaths,
		BootstrapPath: bootstrapPath,
	}); err != nil {
		return nil, err
	}

	return writeBootstrapLayer(ctx, cs, bootstrapPath)
}

// lepton blob footer layout (see src/metadata/blob_footer.rs). The footer is the
// last leptonBlobFooterSize bytes of a full blob and records the absolute
// offsets of the data / bootstrap / blob-meta regions.
const (
	leptonBlobFooterSize  = 4096
	leptonBlobFooterMagic = 0x4c465452
	// bootstrapOffsetField is the byte offset of the u64 bootstrap_offset field
	// within the footer.
	bootstrapOffsetField = 24
)

// stageLeptonMetadata stages a blob from the content store for `lepton merge`
// without materializing the (large) compressed data region.
//
// A lepton full blob is laid out as [compressed data][bootstrap][blob meta]
// [footer]. `lepton merge` only reads the bootstrap and blob meta (located via
// the footer), never the compressed data. So we read just the footer to find
// the bootstrap offset, then write a sparse file that keeps the metadata tail at
// its original absolute offset while leaving [0, bootstrapOffset) as a hole. The
// file is named by the sha256 of its full content (zeros + tail), as required
// by `lepton merge`.
func stageLeptonMetadata(ctx context.Context, cs content.Store, desc ocispec.Descriptor, dir string) (string, error) {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return "", errors.Wrap(err, "open blob reader")
	}
	defer func() { _ = ra.Close() }()

	size := ra.Size()
	if size < leptonBlobFooterSize {
		return "", errors.Errorf("blob is too small for a lepton footer (%d bytes)", size)
	}

	footer := make([]byte, leptonBlobFooterSize)
	if _, err := ra.ReadAt(footer, size-leptonBlobFooterSize); err != nil {
		return "", errors.Wrap(err, "read lepton footer")
	}
	if magic := binary.LittleEndian.Uint32(footer[0:4]); magic != leptonBlobFooterMagic {
		return "", errors.Errorf("not a lepton blob: bad footer magic %#x", magic)
	}
	bootstrapOffset := int64(binary.LittleEndian.Uint64(footer[bootstrapOffsetField : bootstrapOffsetField+8]))
	if bootstrapOffset < 0 || bootstrapOffset > size {
		return "", errors.Errorf("invalid bootstrap offset %d (blob size %d)", bootstrapOffset, size)
	}

	tmp, err := os.CreateTemp(dir, "stage-*")
	if err != nil {
		return "", errors.Wrap(err, "create stage temp file")
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	// The staged file content is bootstrapOffset zero bytes followed by the
	// metadata tail; hash it as we go so we can name the file by its sha256.
	hasher := sha256.New()
	if err := writeZeros(hasher, bootstrapOffset); err != nil {
		return "", errors.Wrap(err, "hash sparse prefix")
	}
	if _, err := tmp.Seek(bootstrapOffset, io.SeekStart); err != nil {
		return "", errors.Wrap(err, "seek to bootstrap offset")
	}
	tail := io.NewSectionReader(ra, bootstrapOffset, size-bootstrapOffset)
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), tail); err != nil {
		return "", errors.Wrap(err, "stage lepton metadata")
	}
	if err := tmp.Close(); err != nil {
		return "", errors.Wrap(err, "close stage temp file")
	}

	dst := filepath.Join(dir, hex.EncodeToString(hasher.Sum(nil)))
	if err := os.Rename(tmpPath, dst); err != nil {
		return "", errors.Wrap(err, "rename staged blob")
	}
	committed = true
	return dst, nil
}

// writeZeros writes n zero bytes to w in bounded chunks.
func writeZeros(w io.Writer, n int64) error {
	if n <= 0 {
		return nil
	}
	buf := make([]byte, 64*1024)
	for n > 0 {
		chunk := int64(len(buf))
		if chunk > n {
			chunk = n
		}
		if _, err := w.Write(buf[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// writeBootstrapLayer packs the bootstrap file into a gzip-compressed tar layer
// (a single `image/image.boot` entry) and commits it to the content store.
func writeBootstrapLayer(ctx context.Context, cs content.Store, bootstrapPath string) (*ocispec.Descriptor, error) {
	bootstrapData, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "read bootstrap")
	}

	// Build the gzip(tar(image/image.boot)) stream while tracking both the
	// compressed (layer) digest and the uncompressed (diff id) digest.
	var compressedBuf bytes.Buffer
	compressedDigester := digest.SHA256.Digester()
	uncompressedDigester := digest.SHA256.Digester()

	gw := gzip.NewWriter(io.MultiWriter(&compressedBuf, compressedDigester.Hash()))
	tw := tar.NewWriter(io.MultiWriter(gw, uncompressedDigester.Hash()))

	if err := writeBootstrapTar(tw, bootstrapData); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, errors.Wrap(err, "close tar writer")
	}
	if err := gw.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}

	compressedDigest := compressedDigester.Digest()
	uncompressedDigest := uncompressedDigester.Digest()
	layerBytes := compressedBuf.Bytes()

	cw, err := content.OpenWriter(ctx, cs, content.WithRef("lepton-bootstrap-"+compressedDigest.String()))
	if err != nil {
		return nil, errors.Wrap(err, "open bootstrap writer")
	}
	defer func() { _ = cw.Close() }()

	if err := content.Copy(ctx, cw, bytes.NewReader(layerBytes), int64(len(layerBytes)), compressedDigest,
		content.WithLabels(map[string]string{
			LayerAnnotationUncompressed: uncompressedDigest.String(),
		}),
	); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, errors.Wrap(err, "commit bootstrap layer")
	}

	return &ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    compressedDigest,
		Size:      int64(len(layerBytes)),
		Annotations: map[string]string{
			LayerAnnotationUncompressed:    uncompressedDigest.String(),
			LayerAnnotationLeptonBootstrap: "true",
		},
	}, nil
}

// writeBootstrapTar writes the `image/` directory and `image/image.boot` file
// entries into tw.
func writeBootstrapTar(tw *tar.Writer, bootstrapData []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:     "image",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		return errors.Wrap(err, "write bootstrap dir header")
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: BootstrapFileNameInLayer,
		Mode: 0o444,
		Size: int64(len(bootstrapData)),
	}); err != nil {
		return errors.Wrap(err, "write bootstrap file header")
	}
	if _, err := tw.Write(bootstrapData); err != nil {
		return errors.Wrap(err, "write bootstrap file")
	}
	return nil
}

// readJSON reads and unmarshals a JSON blob (manifest/index/config) from the
// content store, returning its labels.
func readJSON(ctx context.Context, cs content.Store, x interface{}, desc ocispec.Descriptor) (map[string]string, error) {
	info, err := cs.Info(ctx, desc.Digest)
	if err != nil {
		return nil, errors.Wrap(err, "stat content")
	}
	labels := info.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	b, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return nil, errors.Wrap(err, "read content blob")
	}
	if err := json.Unmarshal(b, x); err != nil {
		return nil, errors.Wrap(err, "unmarshal json")
	}
	return labels, nil
}

// writeJSON marshals x to JSON and commits it to the content store, returning a
// descriptor derived from oldDesc with the new digest and size.
func writeJSON(ctx context.Context, cs content.Store, x interface{}, oldDesc ocispec.Descriptor, labels map[string]string) (*ocispec.Descriptor, error) {
	b, err := json.Marshal(x)
	if err != nil {
		return nil, errors.Wrap(err, "marshal json")
	}
	dgst := digest.SHA256.FromBytes(b)
	ref := fmt.Sprintf("lepton-write-json-%s", dgst.String())
	w, err := content.OpenWriter(ctx, cs, content.WithRef(ref))
	if err != nil {
		return nil, errors.Wrap(err, "open json writer")
	}
	defer func() { _ = w.Close() }()
	if err := content.Copy(ctx, w, bytes.NewReader(b), int64(len(b)), dgst, content.WithLabels(labels)); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, errors.Wrap(err, "commit json")
	}
	newDesc := oldDesc
	newDesc.Size = int64(len(b))
	newDesc.Digest = dgst
	return &newDesc, nil
}
