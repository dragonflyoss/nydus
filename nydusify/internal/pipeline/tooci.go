/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

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
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
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
	// Compressor is the layer compression of the produced OCI image, given as
	// one of the `oci-` prefixed `--compressor` values.
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
	labels, err := oci.Labels(ctx, cs, desc.Digest)
	if err != nil {
		return nil, err
	}
	if err := oci.ReadJSON(ctx, cs, desc, &index); err != nil {
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

	return oci.WriteJSON(ctx, cs, index, desc, labels)
}

func convertManifestToOCI(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt ToOCIOption) (*ocispec.Descriptor, error) {
	var manifest ocispec.Manifest
	manifestLabels, err := oci.Labels(ctx, cs, desc.Digest)
	if err != nil {
		return nil, err
	}
	if err := oci.ReadJSON(ctx, cs, desc, &manifest); err != nil {
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
		layers = append(layers, layer.desc)
		diffIDs = append(diffIDs, layer.diffID)
	}

	manifestLabels = pruneLayerGCLabels(manifestLabels)
	for idx, l := range layers {
		manifestLabels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", idx)] = l.Digest.String()
	}

	var rawConfig json.RawMessage
	configLabels, err := oci.Labels(ctx, cs, manifest.Config.Digest)
	if err != nil {
		return nil, err
	}
	if err := oci.ReadJSON(ctx, cs, manifest.Config, &rawConfig); err != nil {
		return nil, errors.Wrap(err, "read image config")
	}
	newConfig, err := rewriteOCIConfig(rawConfig, diffIDs, len(manifest.Layers)-len(layers))
	if err != nil {
		return nil, errors.Wrap(err, "rewrite image config")
	}
	newConfigDesc, err := oci.WriteJSON(ctx, cs, newConfig, manifest.Config, configLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write image config")
	}
	newConfigDesc.MediaType = ocispec.MediaTypeImageConfig

	manifest.Config = *newConfigDesc
	manifest.Layers = layers
	manifestLabels["containerd.io/gc.ref.content.config"] = newConfigDesc.Digest.String()

	newDesc, err := oci.WriteJSON(ctx, cs, manifest, desc, manifestLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	newDesc.Platform = stripNydusOSFeature(desc.Platform)
	return newDesc, nil
}

// nydusDataLayers returns the layers that carry a filesystem tree, rejecting
// manifests that were never converted to nydus. The bootstrap layer and the
// ondemand blob of an optimized image describe no tree of their own, so they
// are dropped by the reverse conversion.
func nydusDataLayers(layers []ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	blobs, bootstrap, _, err := nydus.SplitLayers(layers)
	if err != nil {
		return nil, err
	}
	if bootstrap == nil || len(blobs) == 0 {
		return nil, errors.New("source is not a nydus image")
	}
	return blobs, nil
}

// unpackedLayer is the OCI layer rebuilt from one nydus data blob.
type unpackedLayer struct {
	desc   ocispec.Descriptor
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
// returning the new descriptor and its diff id.
func unpackLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt ToOCIOption, algo compression.Compression) (ocispec.Descriptor, digest.Digest, error) {
	// The unpacker memory-maps the blob, so it has to exist as a regular file.
	blobPath, err := materializeBlob(ctx, cs, desc, opt.WorkDir)
	if err != nil {
		return ocispec.Descriptor{}, "", err
	}
	defer func() { _ = os.Remove(blobPath) }()

	// The diff id is the digest of the tar before compression, so hash the
	// uncompressed stream while it is being compressed into the content store.
	diffIDer := digest.SHA256.Digester()
	layerDigest, layerSize, err := oci.CommitBlob(ctx, cs, "nydus-to-oci-"+desc.Digest.String(), "",
		func(digest.Digest) map[string]string {
			return map[string]string{nydus.LayerAnnotationUncompressed: diffIDer.Digest().String()}
		},
		func(w io.Writer) error {
			compressor, err := compression.CompressStream(w, algo)
			if err != nil {
				return errors.Wrap(err, "open compressor")
			}
			exportErr := nydus.RunNydusExport(ctx, nydus.ExportOption{
				BuilderPath: opt.BuilderPath,
				BlobPath:    blobPath,
				LogLevel:    opt.LogLevel,
			}, io.MultiWriter(compressor, diffIDer.Hash()))
			if closeErr := compressor.Close(); exportErr == nil {
				exportErr = closeErr
			}
			return exportErr
		},
	)
	if err != nil {
		return ocispec.Descriptor{}, "", err
	}

	diffID := diffIDer.Digest()
	return ocispec.Descriptor{
		MediaType: layerMediaType(algo),
		Digest:    layerDigest,
		Size:      layerSize,
		Annotations: map[string]string{
			nydus.LayerAnnotationUncompressed: diffID.String(),
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
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", errors.Wrap(err, "close blob file")
	}
	return path, nil
}

// rewriteOCIConfig replaces the diff ids of the config and drops the history
// entries of the layers the reverse conversion removed, patching the raw JSON
// so unrelated fields stay byte-for-byte intact.
func rewriteOCIConfig(configJSON json.RawMessage, diffIDs []digest.Digest, droppedLayers int) (json.RawMessage, error) {
	return patchImageConfig(configJSON, diffIDs, func(history []ocispec.History, present bool) ([]ocispec.History, bool) {
		if !present {
			return nil, false
		}
		return trimHistory(history, droppedLayers), true
	})
}

// trimHistory drops the last droppedLayers non-empty history entries. The
// nydus conversion appends the bootstrap and ondemand layers — and their
// history entries — at the tail, so this restores the one-to-one mapping
// between history and the rebuilt layers.
func trimHistory(history []ocispec.History, droppedLayers int) []ocispec.History {
	for i := len(history) - 1; i >= 0 && droppedLayers > 0; i-- {
		if history[i].EmptyLayer {
			continue
		}
		history = append(history[:i], history[i+1:]...)
		droppedLayers--
	}
	return history
}

// ociCompressors maps the `--compressor` values that select a reverse
// conversion to the OCI layer compression they produce.
var ociCompressors = map[string]compression.Compression{
	"oci-gzip": compression.Gzip,
	"oci-zstd": compression.Zstd,
	"oci-tar":  compression.Uncompressed,
}

// IsOCICompressor reports whether a `--compressor` value asks for a nydus
// image to be converted back to OCI rather than the other way round.
func IsOCICompressor(name string) bool {
	_, ok := ociCompressors[name]
	return ok
}

func parseCompressor(name string) (compression.Compression, error) {
	algo, ok := ociCompressors[name]
	if !ok {
		return 0, errors.Errorf("unsupported OCI compressor %q, expected oci-gzip, oci-zstd or oci-tar", name)
	}
	return algo, nil
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
		if feature != nydus.ManifestOSFeatureNydus {
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
