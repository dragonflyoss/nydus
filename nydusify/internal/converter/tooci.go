/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// ToOCIOption configures the reverse conversion from a nydus image back to a
// plain OCI image.
type ToOCIOption struct {
	// BuilderPath is the path (or PATH-resolvable name) of the nydus binary.
	BuilderPath string
	// WorkDir is a scratch directory used to materialize blobs for unpacking.
	WorkDir string
	// Compressor is the OCI layer compression to apply: "gzip", "zstd" or
	// "none".
	Compressor string
	// LogLevel is the log level passed to the nydus binary.
	LogLevel string
}

// ConvertToOCI turns a nydus image back into a plain OCI image.
//
// Every nydus data layer is a self-describing full blob covering exactly one
// OCI layer, so each one is unpacked independently and the merged bootstrap
// layer is dropped. The rebuilt tar streams are not byte-identical to the
// layers the image was originally converted from, so the diff ids — and hence
// the image config — necessarily change.
func ConvertToOCI(ctx context.Context, cs content.Store, srcDesc ocispec.Descriptor, opt ToOCIOption) (*ocispec.Descriptor, error) {
	if _, err := parseCompressor(opt.Compressor); err != nil {
		return nil, err
	}

	switch {
	case images.IsIndexType(srcDesc.MediaType):
		return convertIndexToOCI(ctx, cs, srcDesc, opt)
	case images.IsManifestType(srcDesc.MediaType):
		return convertManifestToOCI(ctx, cs, srcDesc, opt)
	default:
		return nil, errors.Errorf("unsupported source media type %q", srcDesc.MediaType)
	}
}

func convertIndexToOCI(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt ToOCIOption) (*ocispec.Descriptor, error) {
	var index ocispec.Index
	labels, err := readJSON(ctx, cs, &index, desc)
	if err != nil {
		return nil, errors.Wrap(err, "read index json")
	}

	for i, manifest := range index.Manifests {
		newDesc, err := convertManifestToOCI(ctx, cs, manifest, opt)
		if err != nil {
			return nil, errors.Wrapf(err, "convert manifest %s", manifest.Digest)
		}
		newDesc.Platform = stripNydusOSFeature(manifest.Platform)
		index.Manifests[i] = *newDesc
		labels[fmt.Sprintf("containerd.io/gc.ref.content.m.%d", i)] = newDesc.Digest.String()
	}

	return writeJSON(ctx, cs, index, desc, labels)
}

func convertManifestToOCI(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt ToOCIOption) (*ocispec.Descriptor, error) {
	var manifest ocispec.Manifest
	manifestLabels, err := readJSON(ctx, cs, &manifest, desc)
	if err != nil {
		return nil, errors.Wrap(err, "read manifest json")
	}

	blobs, err := nydusDataLayers(manifest.Layers)
	if err != nil {
		return nil, err
	}

	unpacked, err := unpackLayers(ctx, cs, blobs, opt)
	if err != nil {
		return nil, err
	}

	layers := make([]ocispec.Descriptor, 0, len(unpacked))
	diffIDs := make([]digest.Digest, 0, len(unpacked))
	for _, layer := range unpacked {
		if layer.desc == nil {
			continue
		}
		layers = append(layers, *layer.desc)
		diffIDs = append(diffIDs, layer.diffID)
	}
	if len(layers) == 0 {
		return nil, errors.New("no nydus data layer could be unpacked")
	}

	manifestLabels = pruneLayerGCLabels(manifestLabels)
	for idx, l := range layers {
		manifestLabels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", idx)] = l.Digest.String()
	}

	var rawConfig json.RawMessage
	configLabels, err := readJSON(ctx, cs, &rawConfig, manifest.Config)
	if err != nil {
		return nil, errors.Wrap(err, "read image config")
	}
	newConfig, err := rewriteOCIConfig(rawConfig, diffIDs)
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

	newDesc, err := writeJSON(ctx, cs, manifest, desc, manifestLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	newDesc.Platform = stripNydusOSFeature(desc.Platform)
	return newDesc, nil
}

// nydusDataLayers returns the data blob layers of a nydus manifest, rejecting
// manifests that were never converted to nydus.
func nydusDataLayers(layers []ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	blobs := make([]ocispec.Descriptor, 0, len(layers))
	bootstrap := false
	for _, layer := range layers {
		switch {
		case IsNydusBootstrap(layer):
			bootstrap = true
		case IsNydusBlob(layer):
			blobs = append(blobs, layer)
		default:
			return nil, errors.Errorf("layer %s is not a nydus layer (%s)", layer.Digest, layer.MediaType)
		}
	}
	if !bootstrap || len(blobs) == 0 {
		return nil, errors.New("source is not a nydus image")
	}
	return blobs, nil
}

// unpackedLayer is the OCI layer rebuilt from one nydus data blob. A nil desc
// marks a blob that carries no filesystem tree and was skipped.
type unpackedLayer struct {
	desc   *ocispec.Descriptor
	diffID digest.Digest
}

// unpackLayers rebuilds every data blob into an OCI layer, preserving the
// input order. Layers are independent, so they are unpacked concurrently —
// each one spawns a nydus process and compresses its output, and the forward
// conversion parallelizes the same way.
func unpackLayers(ctx context.Context, cs content.Store, blobs []ocispec.Descriptor, opt ToOCIOption) ([]unpackedLayer, error) {
	algo, err := parseCompressor(opt.Compressor)
	if err != nil {
		return nil, err
	}

	unpacked := make([]unpackedLayer, len(blobs))
	eg, egCtx := errgroup.WithContext(ctx)
	// Concurrent layers each stage a full blob copy on disk, so the limit
	// bounds scratch usage as well as CPU.
	eg.SetLimit(min(runtime.GOMAXPROCS(0), len(blobs)))
	for i, blob := range blobs {
		eg.Go(func() error {
			desc, diffID, err := unpackLayer(egCtx, cs, blob, opt, algo)
			if err != nil {
				return errors.Wrapf(err, "unpack nydus layer %s", blob.Digest)
			}
			unpacked[i] = unpackedLayer{desc: desc, diffID: diffID}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return unpacked, nil
}

// unpackLayer turns one nydus data blob back into a compressed OCI layer,
// returning the new descriptor and its diff id. Data-only blobs (the ondemand
// blob of an optimized image) carry no filesystem tree and are skipped, which
// is reported as a nil descriptor.
func unpackLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt ToOCIOption, algo compression.Compression) (*ocispec.Descriptor, digest.Digest, error) {
	// The unpacker memory-maps the blob, so it has to exist as a regular file.
	blobPath, err := materializeBlob(ctx, cs, desc, opt.WorkDir)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = os.Remove(blobPath) }()

	if unpackable, err := blobHasBootstrap(blobPath); err != nil {
		return nil, "", err
	} else if !unpackable {
		log.G(ctx).Infof("skipping data-only nydus blob %s", desc.Digest)
		return nil, "", nil
	}

	cw, err := content.OpenWriter(ctx, cs, content.WithRef("nydus-to-oci-"+desc.Digest.String()))
	if err != nil {
		return nil, "", errors.Wrap(err, "open content writer")
	}
	defer func() { _ = cw.Close() }()

	// The diff id is the digest of the tar before compression, so hash the
	// uncompressed stream while it is being compressed into the content store.
	diffIDer := digest.SHA256.Digester()
	compressor, err := compression.CompressStream(cw, algo)
	if err != nil {
		return nil, "", errors.Wrap(err, "open compressor")
	}
	unpackErr := runNydusToTar(ctx, UnpackOption{
		BuilderPath: opt.BuilderPath,
		BlobPath:    blobPath,
		LogLevel:    opt.LogLevel,
	}, io.MultiWriter(compressor, diffIDer.Hash()))
	if closeErr := compressor.Close(); unpackErr == nil {
		unpackErr = closeErr
	}
	if unpackErr != nil {
		return nil, "", unpackErr
	}

	diffID := diffIDer.Digest()
	layerDigest := cw.Digest()
	if err := cw.Commit(ctx, 0, "", content.WithLabels(map[string]string{
		LayerAnnotationUncompressed: diffID.String(),
	})); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, "", errors.Wrap(err, "commit layer")
	}

	info, err := cs.Info(ctx, layerDigest)
	if err != nil {
		return nil, "", errors.Wrap(err, "stat committed layer")
	}

	return &ocispec.Descriptor{
		MediaType: layerMediaType(algo),
		Digest:    layerDigest,
		Size:      info.Size,
		Annotations: map[string]string{
			LayerAnnotationUncompressed: diffID.String(),
		},
	}, diffID, nil
}

// materializeBlob copies a nydus blob out of the content store into dir and
// returns its path.
func materializeBlob(ctx context.Context, cs content.Store, desc ocispec.Descriptor, dir string) (string, error) {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return "", errors.Wrap(err, "open blob reader")
	}
	defer func() { _ = ra.Close() }()

	path := filepath.Join(dir, desc.Digest.Encoded())
	file, err := os.Create(path)
	if err != nil {
		return "", errors.Wrap(err, "create blob file")
	}
	defer func() { _ = file.Close() }()

	if _, err := io.Copy(file, io.NewSectionReader(ra, 0, ra.Size())); err != nil {
		_ = os.Remove(path)
		return "", errors.Wrap(err, "write blob file")
	}
	return path, nil
}

func blobHasBootstrap(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, errors.Wrap(err, "open blob file")
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return false, errors.Wrap(err, "stat blob file")
	}
	return pkgconv.HasBootstrap(file, info.Size())
}

// rewriteOCIConfig replaces the diff ids of the config and drops the history
// entries the nydus conversion appended, patching the raw JSON so unrelated
// fields stay byte-for-byte intact.
func rewriteOCIConfig(configJSON json.RawMessage, diffIDs []digest.Digest) (json.RawMessage, error) {
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

	if raw, ok := rawConfig["history"]; ok {
		var history []ocispec.History
		if err := json.Unmarshal(raw, &history); err != nil {
			return nil, errors.Wrap(err, "unmarshal image config history")
		}
		kept := history[:0]
		for _, entry := range history {
			if droppedLayerComments[entry.Comment] {
				continue
			}
			kept = append(kept, entry)
		}
		historyRaw, err := json.Marshal(kept)
		if err != nil {
			return nil, errors.Wrap(err, "marshal image config history")
		}
		rawConfig["history"] = historyRaw
	}

	out, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config")
	}
	return out, nil
}

// droppedLayerComments marks the history entries that describe layers the
// reverse conversion removes, so they must not survive into the OCI config.
var droppedLayerComments = map[string]bool{
	"Nydus Bootstrap Layer":     true,
	"Nydus Ondemand Blob Layer": true,
}

func parseCompressor(name string) (compression.Compression, error) {
	switch name {
	case "", "gzip":
		return compression.Gzip, nil
	case "zstd":
		return compression.Zstd, nil
	case "none":
		return compression.Uncompressed, nil
	default:
		return 0, errors.Errorf("unsupported compressor %q, expected gzip, zstd or none", name)
	}
}

func layerMediaType(algo compression.Compression) string {
	switch algo {
	case compression.Gzip:
		return ocispec.MediaTypeImageLayerGzip
	case compression.Zstd:
		return ocispec.MediaTypeImageLayerZstd
	default:
		return ocispec.MediaTypeImageLayer
	}
}

// stripNydusOSFeature drops the lazy-loading marker so the result advertises
// itself as an ordinary OCI image.
func stripNydusOSFeature(platform *ocispec.Platform) *ocispec.Platform {
	if platform == nil || len(platform.OSFeatures) == 0 {
		return platform
	}
	stripped := *platform
	features := make([]string, 0, len(platform.OSFeatures))
	for _, feature := range platform.OSFeatures {
		if feature != ManifestOSFeatureNydus {
			features = append(features, feature)
		}
	}
	stripped.OSFeatures = features
	return &stripped
}

// pruneLayerGCLabels drops the per-layer gc references of the source manifest,
// which no longer match the rebuilt layer list.
func pruneLayerGCLabels(labels map[string]string) map[string]string {
	for key := range labels {
		if _, err := fmt.Sscanf(key, "containerd.io/gc.ref.content.l.%d", new(int)); err == nil {
			delete(labels, key)
		}
	}
	return labels
}
