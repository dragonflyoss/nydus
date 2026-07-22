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
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Source describes one input of a multi-source conversion. Exactly one of the
// fields must be set.
type Source struct {
	// Dir is a local directory path to build into a nydus blob layer.
	Dir string
	// Image is the root descriptor (already pulled into the content store) of
	// an OCI or nydus image whose layers become nydus blob layers.
	Image *ocispec.Descriptor
}

// MultiSourceOption configures a multi-source -> nydus image conversion. The
// sources are stacked in order (first is lowest) and merged into a single
// bootstrap layer.
type MultiSourceOption struct {
	// BuilderPath is the nydus binary path (PATH-resolvable). Defaults to "nydus".
	BuilderPath string
	// WorkDir is a scratch directory for builds, staging and merging.
	WorkDir string
	// ChunkSize is the nydus file chunk size in bytes.
	ChunkSize uint32
	// CompressSize is the nydus group uncompressed size in bytes.
	CompressSize uint32
	// Compressor is the chunk data compressor ("none" or "zstd").
	Compressor string
	// LogLevel is forwarded to the `nydus` subprocesses.
	LogLevel string
	// Platform is the single platform the output manifest targets. Image
	// sources are resolved against it; directory sources are built as-is.
	Platform ocispec.Platform
	// Sources are the conversion inputs in stacking order (lower to upper).
	Sources []Source
	// AppendInBootstrap lists local files to bundle into the bootstrap layer
	// tar alongside image.boot. Files residing inside a directory source are
	// excluded from that source's blob data region.
	AppendInBootstrap []string
}

// ConvertMultiSource converts a mixed list of sources (local directories and
// OCI/nydus images) into a single nydus image manifest: one nydus blob layer
// per directory / per image layer, plus one merged bootstrap layer. The
// converted content is written into cs, ready for pushing to a registry.
//
// The image runtime config (env, entrypoint, ...) is inherited from the last
// (uppermost) image source when present; otherwise a minimal config is
// synthesized.
func ConvertMultiSource(ctx context.Context, cs content.Store, opt MultiSourceOption) (*ocispec.Descriptor, error) {
	if opt.Compressor == "" {
		opt.Compressor = "zstd"
	}
	if opt.ChunkSize == 0 {
		opt.ChunkSize = 1 << 20
	}
	if opt.CompressSize == 0 {
		opt.CompressSize = 1 << 20
	}
	if opt.Platform.OS == "" {
		opt.Platform = platforms.DefaultSpec()
	}
	if len(opt.Sources) == 0 {
		return nil, errors.New("no sources given")
	}

	appendFiles, err := validateAndReadAppendFiles(opt.AppendInBootstrap)
	if err != nil {
		return nil, err
	}

	mergeDir, err := os.MkdirTemp(opt.WorkDir, "multi-merge-")
	if err != nil {
		return nil, errors.Wrap(err, "create merge scratch dir")
	}
	defer func() { _ = os.RemoveAll(mergeDir) }()

	var (
		blobDescs   []ocispec.Descriptor
		stagedPaths []string
		blobMetas   []BlobMetaFile
		baseConfig  json.RawMessage
	)

	for i, src := range opt.Sources {
		switch {
		case src.Dir != "" && src.Image == nil:
			desc, staged, meta, err := buildDirBlob(ctx, cs, opt, src.Dir, mergeDir)
			if err != nil {
				return nil, errors.Wrapf(err, "convert directory source %q", src.Dir)
			}
			blobDescs = append(blobDescs, desc)
			stagedPaths = append(stagedPaths, staged)
			blobMetas = append(blobMetas, meta)
		case src.Image != nil && src.Dir == "":
			descs, config, err := convertImageSource(ctx, cs, opt, *src.Image)
			if err != nil {
				return nil, errors.Wrapf(err, "convert image source %d", i)
			}
			for _, desc := range descs {
				staged, err := stageNydusMetadata(ctx, cs, desc, mergeDir)
				if err != nil {
					return nil, errors.Wrapf(err, "stage blob %s", desc.Digest)
				}
				meta, err := extractBlobMeta(ctx, cs, desc)
				if err != nil {
					return nil, errors.Wrapf(err, "extract blob meta %s", desc.Digest)
				}
				blobDescs = append(blobDescs, desc)
				stagedPaths = append(stagedPaths, staged)
				blobMetas = append(blobMetas, BlobMetaFile{
					Name: desc.Digest.Encoded() + ".blob.meta",
					Data: meta,
				})
			}
			baseConfig = config
		default:
			return nil, errors.Errorf("source %d: exactly one of Dir or Image must be set", i)
		}
	}
	if len(blobDescs) == 0 {
		return nil, errors.New("sources produced no nydus blob layers")
	}

	// Merge all staged blobs (in stacking order) into a single bootstrap.
	bootstrapPath := filepath.Join(mergeDir, "bootstrap")
	if err := runNydusMerge(ctx, MergeBuildOption{
		BuilderPath:   opt.BuilderPath,
		SourcePaths:   stagedPaths,
		BootstrapPath: bootstrapPath,
		LogLevel:      opt.LogLevel,
	}); err != nil {
		return nil, err
	}

	bootstrapData, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "read bootstrap")
	}
	bootstrapDesc, err := WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas, appendFiles)
	if err != nil {
		return nil, errors.Wrap(err, "write bootstrap layer")
	}

	// Assemble the final layer list, diff ids and history.
	layers := make([]ocispec.Descriptor, 0, len(blobDescs)+1)
	layers = append(layers, blobDescs...)
	layers = append(layers, *bootstrapDesc)

	diffIDs := make([]digest.Digest, 0, len(layers))
	history := make([]ocispec.History, 0, len(layers))
	for _, l := range layers[:len(layers)-1] {
		diffIDs = append(diffIDs, digest.Digest(l.Annotations[LayerAnnotationUncompressed]))
		history = append(history, ocispec.History{
			CreatedBy: "Nydus Build", Comment: "Nydus Data Layer",
		})
	}
	diffIDs = append(diffIDs, digest.Digest(bootstrapDesc.Annotations[LayerAnnotationUncompressed]))
	history = append(history, ocispec.History{
		CreatedBy: "Nydus Converter", Comment: "Nydus Bootstrap Layer",
	})

	configJSON, err := buildImageConfig(baseConfig, opt.Platform, diffIDs, history)
	if err != nil {
		return nil, errors.Wrap(err, "build image config")
	}
	configDesc, err := writeJSON(ctx, cs, configJSON, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		return nil, errors.Wrap(err, "write image config")
	}
	configDesc.MediaType = ocispec.MediaTypeImageConfig

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

// buildDirBlob runs `nydus build` on dir, ingests the resulting full blob into
// the content store, stages its metadata into mergeDir for `nydus merge`, and
// extracts its blob meta artifact.
func buildDirBlob(ctx context.Context, cs content.Store, opt MultiSourceOption, dir, mergeDir string) (ocispec.Descriptor, string, BlobMetaFile, error) {
	buildDir, err := os.MkdirTemp(opt.WorkDir, "local-build-")
	if err != nil {
		return ocispec.Descriptor{}, "", BlobMetaFile{}, errors.Wrap(err, "create build scratch dir")
	}
	defer func() { _ = os.RemoveAll(buildDir) }()

	// Pass the append file paths as --exclude flags to `nydus build`. The
	// Rust side resolves each path against the source directory and
	// canonicalizes it, so files outside the source are simply ignored.
	blobPath := filepath.Join(buildDir, "blob.nydus")
	if err := runNydusBuild(ctx, BuildOption{
		BuilderPath:  opt.BuilderPath,
		SourceDir:    dir,
		BlobPath:     blobPath,
		ChunkSize:    opt.ChunkSize,
		CompressSize: opt.CompressSize,
		Compressor:   opt.Compressor,
		LogLevel:     opt.LogLevel,
		Excludes:     opt.AppendInBootstrap,
	}); err != nil {
		return ocispec.Descriptor{}, "", BlobMetaFile{}, err
	}

	blobDesc, err := ingestBlobFile(ctx, cs, blobPath)
	if err != nil {
		return ocispec.Descriptor{}, "", BlobMetaFile{}, errors.Wrap(err, "ingest blob")
	}

	stagedPath, err := stageNydusMetadataFromFile(blobPath, blobDesc.Digest, mergeDir)
	if err != nil {
		return ocispec.Descriptor{}, "", BlobMetaFile{}, errors.Wrap(err, "stage blob for merge")
	}

	metaData, err := extractBlobMetaFromFile(blobPath)
	if err != nil {
		return ocispec.Descriptor{}, "", BlobMetaFile{}, errors.Wrap(err, "extract blob meta")
	}

	return blobDesc, stagedPath, BlobMetaFile{
		Name: blobDesc.Digest.Encoded() + ".blob.meta",
		Data: metaData,
	}, nil
}

// convertImageSource converts every OCI layer of the image rooted at srcDesc
// into a nydus blob layer (layers already in nydus format are reused as-is,
// and an existing bootstrap layer is dropped), then returns the blob layer
// descriptors in stacking order together with the image's raw config JSON.
func convertImageSource(ctx context.Context, cs content.Store, opt MultiSourceOption, srcDesc ocispec.Descriptor) ([]ocispec.Descriptor, json.RawMessage, error) {
	platformMC := platforms.Only(opt.Platform)

	layerFn := LayerConvertFunc(PackOption{
		BuilderPath:  opt.BuilderPath,
		WorkDir:      opt.WorkDir,
		ChunkSize:    opt.ChunkSize,
		CompressSize: opt.CompressSize,
		Compressor:   opt.Compressor,
		LogLevel:     opt.LogLevel,
	})
	// Convert layers only: no post-convert hook, so no per-image bootstrap
	// merge happens here. The caller merges the blobs of all sources at once.
	convertFn := converter.IndexConvertFuncWithHook(layerFn, true, platformMC, converter.ConvertHooks{})

	if err := labelNydusBlobDiffIDs(ctx, cs, srcDesc, platformMC); err != nil {
		return nil, nil, errors.Wrap(err, "label nydus blob diff ids")
	}

	newDesc, err := convertFn(ctx, cs, srcDesc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "convert image layers")
	}
	if newDesc == nil {
		// Nothing was modified (e.g. the source is already a nydus image).
		newDesc = &srcDesc
	}

	manifestDesc, err := resolveManifestDesc(ctx, cs, *newDesc, platformMC)
	if err != nil {
		return nil, nil, err
	}

	var manifest ocispec.Manifest
	if _, err := readJSON(ctx, cs, &manifest, manifestDesc); err != nil {
		return nil, nil, errors.Wrap(err, "read manifest json")
	}

	blobs := make([]ocispec.Descriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if IsNydusBootstrap(layer) {
			// A pre-merged bootstrap of an existing nydus image is dropped;
			// a fresh bootstrap covering all sources is generated instead.
			continue
		}
		if !IsNydusBlob(layer) {
			return nil, nil, errors.Errorf("unsupported layer %s (%s) in image source", layer.Digest, layer.MediaType)
		}
		blobs = append(blobs, layer)
	}

	var config json.RawMessage
	if _, err := readJSON(ctx, cs, &config, manifest.Config); err != nil {
		return nil, nil, errors.Wrap(err, "read image config")
	}
	return blobs, config, nil
}

// buildImageConfig produces the final OCI image config JSON. When base is
// non-nil, only its `rootfs` and `history` fields are replaced so every other
// field (in particular the runtime config) is preserved byte-for-byte;
// otherwise a minimal config is synthesized.
func buildImageConfig(base json.RawMessage, platform ocispec.Platform, diffIDs []digest.Digest, history []ocispec.History) (json.RawMessage, error) {
	if base == nil {
		return json.Marshal(ocispec.Image{
			Platform: platform,
			RootFS: ocispec.RootFS{
				Type:    "layers",
				DiffIDs: diffIDs,
			},
			History: history,
		})
	}

	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal(base, &rawConfig); err != nil {
		return nil, errors.Wrap(err, "unmarshal image config")
	}

	rootFSRaw, err := json.Marshal(ocispec.RootFS{Type: "layers", DiffIDs: diffIDs})
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config rootfs")
	}
	rawConfig["rootfs"] = rootFSRaw

	historyRaw, err := json.Marshal(history)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config history")
	}
	rawConfig["history"] = historyRaw

	return json.Marshal(rawConfig)
}

// labelNydusBlobDiffIDs sets the containerd.io/uncompressed content-store
// label on every nydus blob layer referenced by rootDesc (taken from the layer
// annotation of the same name). A nydus full blob is uncompressed at the layer
// level but starts with compressed chunk data, so without the label
// images.GetDiffID would try to decompress the blob and fail with "magic
// number mismatch". With the label it takes the fast path.
func labelNydusBlobDiffIDs(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) error {
	var manifestDescs []ocispec.Descriptor
	switch {
	case images.IsManifestType(rootDesc.MediaType):
		manifestDescs = []ocispec.Descriptor{rootDesc}
	case images.IsIndexType(rootDesc.MediaType):
		var index ocispec.Index
		if _, err := readJSON(ctx, cs, &index, rootDesc); err != nil {
			return errors.Wrap(err, "read index json")
		}
		for _, m := range index.Manifests {
			if m.Platform == nil || platformMC.Match(*m.Platform) {
				manifestDescs = append(manifestDescs, m)
			}
		}
	default:
		return nil
	}

	for _, manifestDesc := range manifestDescs {
		var manifest ocispec.Manifest
		if _, err := readJSON(ctx, cs, &manifest, manifestDesc); err != nil {
			return errors.Wrap(err, "read manifest json")
		}
		for _, layer := range manifest.Layers {
			uncompressed := layer.Annotations[LayerAnnotationUncompressed]
			if !IsNydusBlob(layer) || uncompressed == "" {
				continue
			}
			info, err := cs.Info(ctx, layer.Digest)
			if err != nil {
				if errdefs.IsNotFound(err) {
					continue
				}
				return errors.Wrapf(err, "stat blob %s", layer.Digest)
			}
			if info.Labels[LayerAnnotationUncompressed] == uncompressed {
				continue
			}
			if info.Labels == nil {
				info.Labels = map[string]string{}
			}
			info.Labels[LayerAnnotationUncompressed] = uncompressed
			if _, err := cs.Update(ctx, info, "labels"); err != nil {
				return errors.Wrapf(err, "label blob %s", layer.Digest)
			}
		}
	}
	return nil
}

// resolveManifestDesc returns the platform-specific manifest descriptor,
// selecting from an index when rootDesc is multi-platform.
func resolveManifestDesc(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (ocispec.Descriptor, error) {
	if images.IsManifestType(rootDesc.MediaType) {
		return rootDesc, nil
	}
	if !images.IsIndexType(rootDesc.MediaType) {
		return ocispec.Descriptor{}, errors.Errorf("unsupported root media type %q", rootDesc.MediaType)
	}

	var index ocispec.Index
	if _, err := readJSON(ctx, cs, &index, rootDesc); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "read index json")
	}
	for _, m := range index.Manifests {
		if m.Platform == nil || platformMC.Match(*m.Platform) {
			return m, nil
		}
	}
	return ocispec.Descriptor{}, errors.New("no manifest matches the requested platform")
}
