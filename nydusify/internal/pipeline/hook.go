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

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// ConvertHookFunc returns a converter.ConvertHookFunc invoked after each blob
// is converted. It hooks index and manifest conversion to merge the per-layer
// nydus blobs into a single bootstrap layer.
func ConvertHookFunc(opt nydus.MergeOption) converter.ConvertHookFunc {
	return func(ctx context.Context, cs content.Store, orgDesc ocispec.Descriptor, newDesc *ocispec.Descriptor) (*ocispec.Descriptor, error) {
		// No conversion happened for this blob: return nil so the parent does
		// not consider it modified. Returning a non-nil descriptor here would
		// mark unconverted blobs (e.g. in-toto attestation layers) as
		// converted, causing their parent manifests to be rewritten and then
		// mistakenly merged as nydus manifests.
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
	if err := oci.ReadJSON(ctx, cs, *newDesc, &index); err != nil {
		return nil, errors.Wrap(err, "read index json")
	}
	if len(index.Manifests) == 1 {
		return &index.Manifests[0], nil
	}
	return newDesc, nil
}

// convertManifest merges all nydus blob layers in the manifest into a single
// nydus bootstrap layer, rewrites the image config, and rewrites the manifest.
func convertManifest(ctx context.Context, cs content.Store, newDesc *ocispec.Descriptor, opt nydus.MergeOption) (*ocispec.Descriptor, error) {
	var manifest ocispec.Manifest
	manifestLabels, err := oci.Labels(ctx, cs, newDesc.Digest)
	if err != nil {
		return nil, err
	}
	if err := oci.ReadJSON(ctx, cs, *newDesc, &manifest); err != nil {
		return nil, errors.Wrap(err, "read manifest json")
	}

	// Only manifests whose layers were all converted to nydus blobs need a
	// bootstrap merge. Anything else (e.g. buildkit attestation manifests with
	// in-toto JSON layers, or already-merged nydus manifests) is passed
	// through unchanged.
	if !isMergeableBlobManifest(manifest) {
		return newDesc, nil
	}

	// Merge the nydus blob layers into a bootstrap layer.
	bootstrapDesc, err := mergeLayers(ctx, cs, manifest.Layers, opt)
	if err != nil {
		return nil, errors.Wrap(err, "merge nydus layers")
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
		if uncompressed := l.Annotations[nydus.LayerAnnotationUncompressed]; uncompressed != "" {
			diffIDs = append(diffIDs, digest.Digest(uncompressed))
		}
	}

	var rawConfig json.RawMessage
	configLabels, err := oci.Labels(ctx, cs, manifest.Config.Digest)
	if err != nil {
		return nil, err
	}
	if err := oci.ReadJSON(ctx, cs, manifest.Config, &rawConfig); err != nil {
		return nil, errors.Wrap(err, "read image config")
	}
	newConfig, err := rewriteBootstrapConfig(rawConfig, diffIDs)
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

	newManifestDesc, err := oci.WriteJSON(ctx, cs, manifest, *newDesc, manifestLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	// Preserve the platform metadata from the input manifest descriptor.
	newManifestDesc.Platform = newDesc.Platform
	return newManifestDesc, nil
}

// rewriteBootstrapConfig appends the bootstrap layer's diff id and history
// entry to the source config (see patchImageConfig for the raw-JSON rationale).
func rewriteBootstrapConfig(configJSON json.RawMessage, diffIDs []digest.Digest) (json.RawMessage, error) {
	return patchImageConfig(configJSON, diffIDs, func(history []ocispec.History, _ bool) ([]ocispec.History, bool) {
		return append(history, ocispec.History{
			CreatedBy: "Nydus Converter",
			Comment:   "Nydus Bootstrap Layer",
		}), true
	})
}

// isMergeableBlobManifest reports whether the manifest is in the mergeable
// pre-merge state: every layer is a converted nydus data blob and no bootstrap
// layer has been appended yet. A finished nydus manifest (blobs followed by a
// bootstrap layer) returns false.
func isMergeableBlobManifest(manifest ocispec.Manifest) bool {
	blobs, bootstrap, optimized, err := nydus.SplitLayers(manifest.Layers)
	return err == nil && bootstrap == nil && optimized == nil && len(blobs) > 0
}

// mergeLayers merges the nydus blob layers (read from the content store) into
// a single bootstrap via nydus.MergeBootstrap and packs the resulting
// bootstrap into a gzip-compressed layer committed to the store.
func mergeLayers(ctx context.Context, cs content.Store, descs []ocispec.Descriptor, opt nydus.MergeOption) (*ocispec.Descriptor, error) {
	layers := make([]nydus.Layer, 0, len(descs))
	for _, desc := range descs {
		ra, err := cs.ReaderAt(ctx, desc)
		if err != nil {
			return nil, errors.Wrapf(err, "open blob %s", desc.Digest)
		}
		defer func() { _ = ra.Close() }()
		layers = append(layers, nydus.Layer{Digest: desc.Digest, ReaderAt: ra})
	}

	bootstrapData, blobMetas, err := nydus.MergeBootstrap(ctx, layers, opt)
	if err != nil {
		return nil, err
	}

	return oci.WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas, opt.AppendFiles)
}
