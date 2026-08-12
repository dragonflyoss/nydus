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

	pkgconv "github.com/dragonflyoss/nydus/nydusify/pkg/converter"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
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
		opt.Compressor = pkgconv.DefaultCompressor
	}
	if opt.ChunkSize == 0 {
		opt.ChunkSize = pkgconv.DefaultChunkSize
	}
	if opt.CompressSize == 0 {
		opt.CompressSize = pkgconv.DefaultCompressSize
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
		blobDescs  []ocispec.Descriptor
		blobLayers []pkgconv.Layer
		baseConfig json.RawMessage
	)

	for i, src := range opt.Sources {
		switch {
		case src.Dir != "" && src.Image == nil:
			blobPath := filepath.Join(mergeDir, fmt.Sprintf("source-%d.blob", i))
			desc, err := buildDirBlob(ctx, cs, opt, src.Dir, blobPath)
			if err != nil {
				return nil, errors.Wrapf(err, "convert directory source %q", src.Dir)
			}
			f, err := os.Open(blobPath)
			if err != nil {
				return nil, errors.Wrap(err, "open built blob")
			}
			defer func() { _ = f.Close() }()
			blobDescs = append(blobDescs, desc)
			blobLayers = append(blobLayers, pkgconv.Layer{Digest: desc.Digest, ReaderAt: io.NewSectionReader(f, 0, desc.Size)})
		case src.Image != nil && src.Dir == "":
			descs, config, err := convertImageSource(ctx, cs, opt, *src.Image)
			if err != nil {
				return nil, errors.Wrapf(err, "convert image source %d", i)
			}
			for _, desc := range descs {
				ra, err := cs.ReaderAt(ctx, desc)
				if err != nil {
					return nil, errors.Wrapf(err, "open blob %s", desc.Digest)
				}
				defer func() { _ = ra.Close() }()
				blobDescs = append(blobDescs, desc)
				blobLayers = append(blobLayers, pkgconv.Layer{Digest: desc.Digest, ReaderAt: ra})
			}
			baseConfig = config
		default:
			return nil, errors.Errorf("source %d: exactly one of Dir or Image must be set", i)
		}
	}
	if len(blobDescs) == 0 {
		return nil, errors.New("sources produced no nydus blob layers")
	}

	// Merge all blobs (in stacking order) into a single bootstrap.
	bootstrapData, blobMetas, err := pkgconv.MergeBootstrap(ctx, blobLayers, pkgconv.MergeOption{
		BuilderPath: opt.BuilderPath,
		WorkDir:     opt.WorkDir,
		LogLevel:    opt.LogLevel,
	})
	if err != nil {
		return nil, err
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
		diffIDs = append(diffIDs, digest.Digest(l.Annotations[pkgconv.LayerAnnotationUncompressed]))
		history = append(history, ocispec.History{
			CreatedBy: "Nydus Build", Comment: "Nydus Data Layer",
		})
	}
	diffIDs = append(diffIDs, digest.Digest(bootstrapDesc.Annotations[pkgconv.LayerAnnotationUncompressed]))
	history = append(history, ocispec.History{
		CreatedBy: "Nydus Converter", Comment: "Nydus Bootstrap Layer",
	})

	configJSON, err := buildImageConfig(baseConfig, opt.Platform, diffIDs, history)
	if err != nil {
		return nil, errors.Wrap(err, "build image config")
	}
	configDesc, err := WriteJSON(ctx, cs, configJSON, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
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
	manifestDesc, err := WriteJSON(ctx, cs, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, labels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	return manifestDesc, nil
}

// buildDirBlob runs `nydus build` on dir, writing the resulting full blob to
// blobPath (kept for the later merge), and ingests it into the content store.
func buildDirBlob(ctx context.Context, cs content.Store, opt MultiSourceOption, dir, blobPath string) (ocispec.Descriptor, error) {
	// Pass the append file paths as --exclude flags to `nydus build`. The
	// Rust side resolves each path against the source directory and
	// canonicalizes it, so files outside the source are simply ignored.
	if err := pkgconv.RunNydusBuild(ctx, pkgconv.BuildOption{
		BuilderPath:  opt.BuilderPath,
		SourceDir:    dir,
		BlobPath:     blobPath,
		ChunkSize:    opt.ChunkSize,
		CompressSize: opt.CompressSize,
		Compressor:   opt.Compressor,
		LogLevel:     opt.LogLevel,
		Excludes:     opt.AppendInBootstrap,
	}); err != nil {
		return ocispec.Descriptor{}, err
	}

	blobDesc, err := IngestBlobFile(ctx, cs, blobPath, "")
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "ingest blob")
	}
	return blobDesc, nil
}

// convertImageSource converts every OCI layer of the image rooted at srcDesc
// into a nydus blob layer (layers already in nydus format are reused as-is,
// and an existing bootstrap layer is dropped), then returns the blob layer
// descriptors in stacking order together with the image's raw config JSON.
func convertImageSource(ctx context.Context, cs content.Store, opt MultiSourceOption, srcDesc ocispec.Descriptor) ([]ocispec.Descriptor, json.RawMessage, error) {
	platformMC := platforms.Only(opt.Platform)

	layerFn := LayerConvertFunc(pkgconv.PackOption{
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

	manifestDesc, err := oci.ResolveManifest(ctx, cs, *newDesc, platformMC)
	if err != nil {
		return nil, nil, err
	}

	var manifest ocispec.Manifest
	if err := oci.ReadJSON(ctx, cs, manifestDesc, &manifest); err != nil {
		return nil, nil, errors.Wrap(err, "read manifest json")
	}

	blobs := make([]ocispec.Descriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if pkgconv.IsNydusBootstrap(layer) {
			// A pre-merged bootstrap of an existing nydus image is dropped;
			// a fresh bootstrap covering all sources is generated instead.
			continue
		}
		if !pkgconv.IsNydusBlob(layer) {
			return nil, nil, errors.Errorf("unsupported layer %s (%s) in image source", layer.Digest, layer.MediaType)
		}
		blobs = append(blobs, layer)
	}

	var config json.RawMessage
	if err := oci.ReadJSON(ctx, cs, manifest.Config, &config); err != nil {
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

	return patchImageConfig(base, diffIDs, func(_ []ocispec.History, _ bool) ([]ocispec.History, bool) {
		return history, true
	})
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
		if err := oci.ReadJSON(ctx, cs, rootDesc, &index); err != nil {
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
		if err := oci.ReadJSON(ctx, cs, manifestDesc, &manifest); err != nil {
			return errors.Wrap(err, "read manifest json")
		}
		for _, layer := range manifest.Layers {
			uncompressed := layer.Annotations[pkgconv.LayerAnnotationUncompressed]
			if !pkgconv.IsNydusBlob(layer) || uncompressed == "" {
				continue
			}
			info, err := cs.Info(ctx, layer.Digest)
			if err != nil {
				if errdefs.IsNotFound(err) {
					continue
				}
				return errors.Wrapf(err, "stat blob %s", layer.Digest)
			}
			if info.Labels[pkgconv.LayerAnnotationUncompressed] == uncompressed {
				continue
			}
			if info.Labels == nil {
				info.Labels = map[string]string{}
			}
			info.Labels[pkgconv.LayerAnnotationUncompressed] = uncompressed
			if _, err := cs.Update(ctx, info, "labels"); err != nil {
				return errors.Wrapf(err, "label blob %s", layer.Digest)
			}
		}
	}
	return nil
}
