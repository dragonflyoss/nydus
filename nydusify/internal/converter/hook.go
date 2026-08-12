/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/errdefs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// ConvertHookFunc returns a converter.ConvertHookFunc invoked after each blob
// is converted. It hooks index and manifest conversion to merge the per-layer
// nydus blobs into a single bootstrap layer.
func ConvertHookFunc(opt pkgconv.MergeOption) converter.ConvertHookFunc {
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
func convertManifest(ctx context.Context, cs content.Store, newDesc *ocispec.Descriptor, opt pkgconv.MergeOption) (*ocispec.Descriptor, error) {
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
		if uncompressed := l.Annotations[pkgconv.LayerAnnotationUncompressed]; uncompressed != "" {
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

	newConfigDesc, err := WriteJSON(ctx, cs, newConfig, manifest.Config, configLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write image config")
	}
	newConfigDesc.MediaType = ocispec.MediaTypeImageConfig
	manifest.Config = *newConfigDesc
	manifest.Layers = layers
	manifestLabels["containerd.io/gc.ref.content.config"] = newConfigDesc.Digest.String()

	newManifestDesc, err := WriteJSON(ctx, cs, manifest, *newDesc, manifestLabels)
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
// patchImageConfig replaces only the `rootfs` diff ids of a raw image config
// and lets historyFn rewrite the `history` field, keeping every other field
// byte-for-byte intact.
//
// Decoding the whole config into ocispec.Image and re-marshaling it would drop
// empty-but-present fields via `omitempty` (e.g. `"Cmd": []` is re-encoded as
// absent and then decodes back as a nil slice). The nydus config would then no
// longer be reflect.DeepEqual to the untouched source OCI config, and
// `nydusify check` would fail the manifest config-consistency rule.
func patchImageConfig(configJSON json.RawMessage, diffIDs []digest.Digest, historyFn func(history []ocispec.History, present bool) ([]ocispec.History, bool)) (json.RawMessage, error) {
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
	if rootFS.Type == "" {
		rootFS.Type = "layers"
	}
	rootFS.DiffIDs = diffIDs
	rootFSRaw, err := json.Marshal(rootFS)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config rootfs")
	}
	rawConfig["rootfs"] = rootFSRaw

	var history []ocispec.History
	rawHistory, present := rawConfig["history"]
	if present {
		if err := json.Unmarshal(rawHistory, &history); err != nil {
			return nil, errors.Wrap(err, "unmarshal image config history")
		}
	}
	if newHistory, write := historyFn(history, present); write {
		historyRaw, err := json.Marshal(newHistory)
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
	if len(manifest.Layers) == 0 {
		return false
	}
	for _, layer := range manifest.Layers {
		if !pkgconv.IsNydusBlob(layer) {
			return false
		}
	}
	return true
}

// mergeLayers merges the nydus blob layers (read from the content store) into
// a single bootstrap via pkg/converter.MergeBootstrap and packs the resulting
// bootstrap into a gzip-compressed layer committed to the store.
func mergeLayers(ctx context.Context, cs content.Store, descs []ocispec.Descriptor, opt pkgconv.MergeOption) (*ocispec.Descriptor, error) {
	layers := make([]pkgconv.Layer, 0, len(descs))
	for _, desc := range descs {
		ra, err := cs.ReaderAt(ctx, desc)
		if err != nil {
			return nil, errors.Wrapf(err, "open blob %s", desc.Digest)
		}
		defer func() { _ = ra.Close() }()
		layers = append(layers, pkgconv.Layer{Digest: desc.Digest, ReaderAt: ra})
	}

	bootstrapData, blobMetas, err := pkgconv.MergeBootstrap(ctx, layers, opt)
	if err != nil {
		return nil, err
	}

	return WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas, opt.AppendFiles)
}

// WriteBootstrapLayer packs bootstrap bytes and per-layer blob meta artifacts
// into a gzip-compressed tar layer (under `image/`) and commits it to the
// content store, returning the bootstrap layer descriptor. If appendFiles is
// non-empty, each file is placed under "image/" alongside image.boot.
func WriteBootstrapLayer(ctx context.Context, cs content.Store, bootstrapData []byte, blobMetas []pkgconv.BlobMetaFile, appendFiles []pkgconv.AppendFile) (*ocispec.Descriptor, error) {
	var compressedBuf bytes.Buffer
	compressedDigester := digest.SHA256.Digester()
	uncompressedDigester := digest.SHA256.Digester()

	gw := gzip.NewWriter(io.MultiWriter(&compressedBuf, compressedDigester.Hash()))
	tw := tar.NewWriter(io.MultiWriter(gw, uncompressedDigester.Hash()))

	if err := pkgconv.WriteBootstrapTar(tw, bootstrapData, blobMetas, appendFiles); err != nil {
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

	cw, err := content.OpenWriter(ctx, cs, content.WithRef("nydus-bootstrap-"+compressedDigest.String()))
	if err != nil {
		return nil, errors.Wrap(err, "open bootstrap writer")
	}
	defer func() { _ = cw.Close() }()

	if err := content.Copy(ctx, cw, bytes.NewReader(layerBytes), int64(len(layerBytes)), compressedDigest,
		content.WithLabels(map[string]string{
			pkgconv.LayerAnnotationUncompressed: uncompressedDigest.String(),
		}),
	); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, errors.Wrap(err, "commit bootstrap layer")
	}

	return &ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    compressedDigest,
		Size:      int64(len(layerBytes)),
		Annotations: map[string]string{
			pkgconv.LayerAnnotationUncompressed:   uncompressedDigest.String(),
			pkgconv.LayerAnnotationNydusBootstrap: "true",
			pkgconv.LayerAnnotationNydusFsVersion: pkgconv.NydusFsVersion,
		},
	}, nil
}

// WriteJSON marshals x to JSON and commits it to the content store, returning a
// descriptor derived from oldDesc with the new digest and size.
func WriteJSON(ctx context.Context, cs content.Store, x interface{}, oldDesc ocispec.Descriptor, labels map[string]string) (*ocispec.Descriptor, error) {
	b, err := json.Marshal(x)
	if err != nil {
		return nil, errors.Wrap(err, "marshal json")
	}
	dgst := digest.SHA256.FromBytes(b)
	ref := fmt.Sprintf("nydus-write-json-%s", dgst.String())
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
