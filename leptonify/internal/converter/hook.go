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
	"encoding/binary"
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
	// LogLevel is the log level forwarded to `lepton merge` (trace/debug/info/
	// warn/error). Defaults to "info" when empty.
	LogLevel string
}

// ConvertHookFunc returns a converter.ConvertHookFunc invoked after each blob
// is converted. It hooks index and manifest conversion to merge the per-layer
// lepton blobs into a single bootstrap layer.
func ConvertHookFunc(opt MergeOption) converter.ConvertHookFunc {
	return func(ctx context.Context, cs content.Store, orgDesc ocispec.Descriptor, newDesc *ocispec.Descriptor) (*ocispec.Descriptor, error) {
		// No conversion happened for this blob: return nil so the parent does
		// not consider it modified. Returning a non-nil descriptor here would
		// mark unconverted blobs (e.g. in-toto attestation layers) as
		// converted, causing their parent manifests to be rewritten and then
		// mistakenly merged as lepton manifests.
		if newDesc == nil {
			return nil, nil
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

	// Only manifests whose layers were all converted to lepton blobs need a
	// bootstrap merge. Anything else (e.g. buildkit attestation manifests with
	// in-toto JSON layers, or already-merged lepton manifests) is passed
	// through unchanged.
	if !isLeptonManifest(manifest) {
		return newDesc, nil
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
	diffIDs := make([]digest.Digest, 0, len(layers))
	for _, l := range layers {
		if uncompressed := l.Annotations[LayerAnnotationUncompressed]; uncompressed != "" {
			diffIDs = append(diffIDs, digest.Digest(uncompressed))
		}
	}

	var rawConfig json.RawMessage
	configLabels, err := readJSON(ctx, cs, &rawConfig, manifest.Config)
	if err != nil {
		return nil, errors.Wrap(err, "read image config")
	}
	newConfig, err := rewriteBootstrapConfig(rawConfig, diffIDs)
	if err != nil {
		return nil, errors.Wrap(err, "rewrite image config")
	}

	newConfigDesc, err := writeJSON(ctx, cs, newConfig, manifest.Config, configLabels)
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

// rewriteBootstrapConfig updates an OCI image config for the merged bootstrap
// layer. It patches only the `rootfs` (diff ids) and `history` fields of the
// raw config JSON and leaves every other field — in particular the runtime
// `config` (env/cmd/entrypoint/working dir/etc.) — byte-for-byte intact.
//
// Decoding the whole config into ocispec.Image and re-marshaling it would drop
// empty-but-present fields via `omitempty` (e.g. `"Cmd": []` is re-encoded as
// absent and then decodes back as a nil slice). The lepton config would then no
// longer be reflect.DeepEqual to the untouched source OCI config, and
// `leptonify check` would fail the manifest config-consistency rule.
func rewriteBootstrapConfig(configJSON json.RawMessage, diffIDs []digest.Digest) (json.RawMessage, error) {
	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal(configJSON, &rawConfig); err != nil {
		return nil, errors.Wrap(err, "unmarshal image config")
	}

	var rootFS ocispec.RootFS
	if raw, ok := rawConfig["rootfs"]; ok {
		if err := json.Unmarshal(raw, &rootFS); err != nil {
			return nil, errors.Wrap(err, "unmarshal image config rootfs")
		}
	}
	rootFS.DiffIDs = diffIDs
	rootFSRaw, err := json.Marshal(rootFS)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config rootfs")
	}
	rawConfig["rootfs"] = rootFSRaw

	var history []ocispec.History
	if raw, ok := rawConfig["history"]; ok {
		if err := json.Unmarshal(raw, &history); err != nil {
			return nil, errors.Wrap(err, "unmarshal image config history")
		}
	}
	history = append(history, ocispec.History{
		CreatedBy: "Lepton Converter",
		Comment:   "Lepton Bootstrap Layer",
	})
	historyRaw, err := json.Marshal(history)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config history")
	}
	rawConfig["history"] = historyRaw

	out, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config")
	}
	return out, nil
}

// isLeptonManifest reports whether every layer of the manifest is a converted
// lepton data blob, i.e. the manifest is ready for a bootstrap merge.
func isLeptonManifest(manifest ocispec.Manifest) bool {
	if len(manifest.Layers) == 0 {
		return false
	}
	for _, layer := range manifest.Layers {
		if !IsLeptonBlob(layer) {
			return false
		}
	}
	return true
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
	blobMetas := make([]BlobMetaFile, 0, len(descs))
	for _, desc := range descs {
		blobPath, err := stageLeptonMetadata(ctx, cs, desc, mergeDir)
		if err != nil {
			return nil, errors.Wrapf(err, "stage blob %s", desc.Digest)
		}
		sourcePaths = append(sourcePaths, blobPath)

		meta, err := extractBlobMeta(ctx, cs, desc)
		if err != nil {
			return nil, errors.Wrapf(err, "extract blob meta %s", desc.Digest)
		}
		blobMetas = append(blobMetas, BlobMetaFile{
			Name: desc.Digest.Encoded() + ".blob.meta",
			Data: meta,
		})
	}

	bootstrapPath := filepath.Join(mergeDir, "bootstrap")
	if err := runLeptonMerge(ctx, MergeBuildOption{
		BuilderPath:   opt.BuilderPath,
		SourcePaths:   sourcePaths,
		BootstrapPath: bootstrapPath,
		LogLevel:      opt.LogLevel,
	}); err != nil {
		return nil, err
	}

	return writeBootstrapLayer(ctx, cs, bootstrapPath, blobMetas)
}

// lepton blob footer layout (see src/metadata/blob_footer.rs). The footer is the
// last leptonBlobFooterSize bytes of a full blob and records the absolute
// offsets of the data / bootstrap / blob-meta regions.
const (
	leptonBlobFooterSize  = 4096
	leptonBlobFooterMagic = 0x4c465452
	leptonBlockSize       = 4096
	// bootstrapOffsetField is the byte offset of the u64 bootstrap_offset field
	// within the footer.
	bootstrapOffsetField = 24
	// blobMetaOffsetField is the byte offset of the u64 blob_meta_offset field
	// within the footer.
	blobMetaOffsetField = 32
	// blobMetaBlocksField is the byte offset of the u32 blob_meta_blocks field
	// within the footer.
	blobMetaBlocksField = 52
)

// BlobMetaFile is a per-layer blob meta artifact packed into the bootstrap layer
// alongside image.boot, named "<full_blob_sha256>.blob.meta".
type BlobMetaFile struct {
	Name string
	Data []byte
}

// stageLeptonMetadata stages a blob from the content store for `lepton merge`
// without materializing the (large) compressed data region.
//
// A lepton full blob is laid out as [compressed data][bootstrap][blob meta]
// [footer]. `lepton merge` only reads the bootstrap and blob meta (located via
// the footer), never the compressed data. So we read just the footer to find
// the bootstrap offset, then write a sparse file that keeps the metadata tail at
// its original absolute offset while leaving [0, bootstrapOffset) as a hole. The
// file is named by the blob's full digest (desc.Digest), which `lepton merge`
// records verbatim in the device slot so a registry backend can address the
// blob by the same digest.
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

	// The staged file content is bootstrapOffset zero bytes (a sparse hole)
	// followed by the metadata tail at its original absolute offset.
	if _, err := tmp.Seek(bootstrapOffset, io.SeekStart); err != nil {
		return "", errors.Wrap(err, "seek to bootstrap offset")
	}
	tail := io.NewSectionReader(ra, bootstrapOffset, size-bootstrapOffset)
	if _, err := io.Copy(tmp, tail); err != nil {
		return "", errors.Wrap(err, "stage lepton metadata")
	}
	if err := tmp.Close(); err != nil {
		return "", errors.Wrap(err, "close stage temp file")
	}

	// Name the staged source by the blob's full digest; `lepton merge` uses the
	// file name as the device slot blob id.
	dst := filepath.Join(dir, desc.Digest.Encoded())
	if err := os.Rename(tmpPath, dst); err != nil {
		return "", errors.Wrap(err, "rename staged blob")
	}
	committed = true
	return dst, nil
}

// extractBlobMeta reads the blob meta region of a lepton full blob from the
// content store, locating it via the trailing footer. The returned bytes are the
// exact `<full_blob_sha256>.blob.meta` artifact produced by `lepton build`.
func extractBlobMeta(ctx context.Context, cs content.Store, desc ocispec.Descriptor) ([]byte, error) {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, errors.Wrap(err, "open blob reader")
	}
	defer func() { _ = ra.Close() }()

	size := ra.Size()
	if size < leptonBlobFooterSize {
		return nil, errors.Errorf("blob is too small for a lepton footer (%d bytes)", size)
	}

	footer := make([]byte, leptonBlobFooterSize)
	if _, err := ra.ReadAt(footer, size-leptonBlobFooterSize); err != nil {
		return nil, errors.Wrap(err, "read lepton footer")
	}
	if magic := binary.LittleEndian.Uint32(footer[0:4]); magic != leptonBlobFooterMagic {
		return nil, errors.Errorf("not a lepton blob: bad footer magic %#x", magic)
	}
	blobMetaOffset := int64(binary.LittleEndian.Uint64(footer[blobMetaOffsetField : blobMetaOffsetField+8]))
	blobMetaSize := int64(binary.LittleEndian.Uint32(footer[blobMetaBlocksField:blobMetaBlocksField+4])) * leptonBlockSize
	if blobMetaOffset < 0 || blobMetaSize <= 0 || blobMetaOffset+blobMetaSize > size {
		return nil, errors.Errorf("invalid blob meta region [%d,+%d) (blob size %d)", blobMetaOffset, blobMetaSize, size)
	}

	buf := make([]byte, blobMetaSize)
	if _, err := ra.ReadAt(buf, blobMetaOffset); err != nil {
		return nil, errors.Wrap(err, "read blob meta region")
	}
	return buf, nil
}

// writeBootstrapLayer packs the bootstrap file and the per-layer blob meta
// artifacts into a gzip-compressed tar layer (under `image/`) and commits it to
// the content store.
func writeBootstrapLayer(ctx context.Context, cs content.Store, bootstrapPath string, blobMetas []BlobMetaFile) (*ocispec.Descriptor, error) {
	bootstrapData, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "read bootstrap")
	}
	return WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas)
}

// WriteBootstrapLayer packs bootstrap bytes and per-layer blob meta artifacts
// into a gzip-compressed tar layer (under `image/`) and commits it to the
// content store, returning the bootstrap layer descriptor.
func WriteBootstrapLayer(ctx context.Context, cs content.Store, bootstrapData []byte, blobMetas []BlobMetaFile) (*ocispec.Descriptor, error) {
	// Build the gzip(tar(image/...)) stream while tracking both the compressed
	// (layer) digest and the uncompressed (diff id) digest.
	var compressedBuf bytes.Buffer
	compressedDigester := digest.SHA256.Digester()
	uncompressedDigester := digest.SHA256.Digester()

	gw := gzip.NewWriter(io.MultiWriter(&compressedBuf, compressedDigester.Hash()))
	tw := tar.NewWriter(io.MultiWriter(gw, uncompressedDigester.Hash()))

	if err := writeBootstrapTar(tw, bootstrapData, blobMetas); err != nil {
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
			LayerAnnotationLeptonFsVersion: LeptonFsVersion,
		},
	}, nil
}

// writeBootstrapTar writes the `image/` directory, the `image/image.boot` file,
// and one `image/<full_blob_sha256>.blob.meta` entry per layer into tw.
func writeBootstrapTar(tw *tar.Writer, bootstrapData []byte, blobMetas []BlobMetaFile) error {
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
	for _, meta := range blobMetas {
		if err := tw.WriteHeader(&tar.Header{
			Name: BlobMetaDirInLayer + "/" + meta.Name,
			Mode: 0o444,
			Size: int64(len(meta.Data)),
		}); err != nil {
			return errors.Wrapf(err, "write blob meta header %s", meta.Name)
		}
		if _, err := tw.Write(meta.Data); err != nil {
			return errors.Wrapf(err, "write blob meta %s", meta.Name)
		}
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

// WriteJSON marshals x to JSON and commits it to the content store, returning a
// descriptor derived from oldDesc with the new digest and size.
func WriteJSON(ctx context.Context, cs content.Store, x interface{}, oldDesc ocispec.Descriptor, labels map[string]string) (*ocispec.Descriptor, error) {
	return writeJSON(ctx, cs, x, oldDesc, labels)
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
