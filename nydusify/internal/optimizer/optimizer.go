/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package optimizer rebuilds a nydus image around a recorded access pattern
// for the optimize command: it runs `nydus optimize` against the source
// bootstrap and publishes a copy of the image with an appended ondemand blob
// layer and a rewritten bootstrap.
package optimizer

import (
	"bytes"
	"cmp"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// OptimizeOption configures an Optimizer.
type OptimizeOption struct {
	// Source is the nydus image reference to optimize. Required.
	Source string
	// Target is the optimized nydus image reference to push. Required.
	Target string
	// Pattern is the path to a JSON access-pattern file (the same document
	// served by the `/trace` endpoint). Required.
	Pattern string
	// BuilderPath is the nydus binary path (PATH-resolvable). Defaults to "nydus".
	BuilderPath string
	// WorkDir is the scratch directory backing the content store and the
	// optimize staging area. It must already exist.
	WorkDir string
	// SourceInsecure skips TLS certificate verification for the source registry.
	SourceInsecure bool
	// SourcePlainHTTP uses plain HTTP to talk to the source registry.
	SourcePlainHTTP bool
	// TargetInsecure skips TLS certificate verification for the target registry.
	TargetInsecure bool
	// TargetPlainHTTP uses plain HTTP to talk to the target registry.
	TargetPlainHTTP bool
	// LogLevel is the log level forwarded to the `nydus` subprocess. Defaults
	// to "info" when empty.
	LogLevel string
	// PlatformMC selects which platform to optimize. Defaults to the host
	// platform.
	PlatformMC platforms.MatchComparer
}

// Optimizer builds an "ondemand" blob from a recorded block group access pattern and
// publishes an optimized copy of a nydus image: the original data layers are
// reused as-is, an ondemand blob layer is appended, and the bootstrap layer is
// rewritten so the runtime prefetches the ondemand blob first.
type Optimizer struct {
	opt OptimizeOption
}

// NewOptimizer creates an Optimizer.
func NewOptimizer(opt OptimizeOption) (*Optimizer, error) {
	if opt.Source == "" {
		return nil, errors.New("source must be provided")
	}
	if opt.Target == "" {
		return nil, errors.New("target must be provided")
	}
	if opt.Pattern == "" {
		return nil, errors.New("pattern must be provided")
	}
	if opt.PlatformMC == nil {
		opt.PlatformMC = platforms.Default()
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "info"
	}
	return &Optimizer{opt: opt}, nil
}

// ondemandDigestPattern matches the `ONDEMAND BLOB DIGEST  <hex>` table row
// printed by `nydus optimize`.
var ondemandDigestPattern = regexp.MustCompile(`ONDEMAND BLOB DIGEST\s+([0-9a-f]{64})`)

// Optimize pulls the source nydus image, runs `nydus optimize` against its
// bootstrap with the recorded access patterns, and pushes the optimized image
// to the target reference.
func (o *Optimizer) Optimize(ctx context.Context) error {
	contentDir := filepath.Join(o.opt.WorkDir, "content")
	scratchDir := filepath.Join(o.opt.WorkDir, "scratch")
	for _, d := range []string{contentDir, scratchDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %q", d)
		}
	}

	provider, err := remote.NewProvider(remote.Option{
		WorkDir:         contentDir,
		SourceInsecure:  o.opt.SourceInsecure,
		SourcePlainHTTP: o.opt.SourcePlainHTTP,
		TargetInsecure:  o.opt.TargetInsecure,
		TargetPlainHTTP: o.opt.TargetPlainHTTP,
		PlatformMC:      o.opt.PlatformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}
	cs := provider.ContentStore()

	img, err := nydusfs.LoadImage(ctx, provider, o.opt.Source, o.opt.PlatformMC, remote.PullAll, remote.Source)
	if err != nil {
		return errors.Wrapf(err, "load source %q", o.opt.Source)
	}
	if img.Kind != nydusfs.KindNydus {
		return errors.Errorf("source %q is not a nydus image", o.opt.Source)
	}
	if img.Bootstrap == nil {
		return errors.New("nydus image is missing its bootstrap layer")
	}

	stageDir, err := os.MkdirTemp(scratchDir, "optimize-")
	if err != nil {
		return errors.Wrap(err, "create optimize scratch dir")
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	// Extract the parent bootstrap and the per-layer blob metas, and seed the
	// cache dir with the metas so `nydus optimize` loads source metadata from
	// disk and only fetches block group data ranges from the registry.
	bootDir := filepath.Join(stageDir, "bootstrap")
	bootstrapPath, blobMetaPaths, err := nydusfs.ExtractBootstrapLayer(ctx, cs, *img.Bootstrap, bootDir)
	if err != nil {
		return errors.Wrap(err, "extract bootstrap")
	}
	cacheDir := filepath.Join(stageDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return errors.Wrap(err, "create cache dir")
	}
	if err := nydusfs.LinkBlobMetaFiles(ctx, blobMetaPaths, cacheDir); err != nil {
		return errors.Wrap(err, "link blob meta to cache")
	}

	configPath := filepath.Join(stageDir, "config.yaml")
	if _, err := nydusfs.WriteRegistryConfig(provider, remote.Source, img, cacheDir, configPath, false); err != nil {
		return errors.Wrap(err, "generate storage config")
	}

	blobDir := filepath.Join(stageDir, "blobs")
	optimizedBootstrapPath := filepath.Join(stageDir, "image.boot.optimized")
	ondemandHex, err := o.runNydusOptimize(ctx, bootstrapPath, optimizedBootstrapPath, blobDir, configPath)
	if err != nil {
		return err
	}
	log.G(ctx).Infof("built ondemand blob %s", ondemandHex)

	// Commit the ondemand blob as a nydus data layer.
	ondemandDesc, err := ingestDigestNamedBlobFile(ctx, cs, filepath.Join(blobDir, ondemandHex))
	if err != nil {
		return errors.Wrap(err, "commit ondemand blob")
	}

	// Rebuild the bootstrap layer tar: the rewritten image.boot, the original
	// per-layer blob metas, and the ondemand blob meta.
	bootstrapData, err := os.ReadFile(optimizedBootstrapPath)
	if err != nil {
		return errors.Wrap(err, "read optimized bootstrap")
	}
	blobMetas := make([]nydus.BlobMetaFile, 0, len(blobMetaPaths)+1)
	for _, p := range blobMetaPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return errors.Wrapf(err, "read blob meta %q", p)
		}
		blobMetas = append(blobMetas, nydus.BlobMetaFile{Name: filepath.Base(p), Data: data})
	}
	ondemandMeta, err := os.ReadFile(filepath.Join(blobDir, ondemandHex+".blob.meta"))
	if err != nil {
		return errors.Wrap(err, "read ondemand blob meta")
	}
	blobMetas = append(blobMetas, nydus.BlobMetaFile{Name: ondemandHex + ".blob.meta", Data: ondemandMeta})

	bootstrapDesc, err := oci.WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas, nil)
	if err != nil {
		return errors.Wrap(err, "write bootstrap layer")
	}

	manifestDesc, err := o.writeOptimizedImage(ctx, cs, img, *ondemandDesc, *bootstrapDesc)
	if err != nil {
		return errors.Wrap(err, "write optimized image")
	}

	log.G(ctx).Infof("pushing optimized image %s", o.opt.Target)
	if err := provider.Push(ctx, *manifestDesc, o.opt.Target); err != nil {
		return errors.Wrapf(err, "push %q", o.opt.Target)
	}
	log.G(ctx).Infof("done: %s -> %s (%s)", o.opt.Source, o.opt.Target, manifestDesc.Digest)
	return nil
}

// runNydusOptimize invokes `nydus optimize` and returns the ondemand blob
// digest hex parsed from its output.
func (o *Optimizer) runNydusOptimize(ctx context.Context, parentBootstrap, bootstrap, blobDir, configPath string) (string, error) {
	args := []string{
		"optimize",
		"--parent-bootstrap", parentBootstrap,
		"--bootstrap", bootstrap,
		"--blob-dir", blobDir,
		"--config", configPath,
		"--log-level", cmp.Or(o.opt.LogLevel, nydus.DefaultLogLevel),
		"--trace-file", o.opt.Pattern,
	}
	cmd := exec.CommandContext(ctx, cmp.Or(o.opt.BuilderPath, nydus.DefaultBuilder), args...)
	var output bytes.Buffer
	cmd.Stdout = io.MultiWriter(&output, os.Stderr)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", errors.Wrap(err, "run nydus optimize")
	}
	match := ondemandDigestPattern.FindSubmatch(output.Bytes())
	if match == nil {
		return "", errors.New("nydus optimize did not report an ondemand blob digest")
	}
	return string(match[1]), nil
}

// ingestDigestNamedBlobFile commits a nydus blob file into the content store,
// trusting the file name as its SHA-256 digest (the content store verifies it
// on commit), and marks it as the ondemand blob appended by optimize.
func ingestDigestNamedBlobFile(ctx context.Context, cs content.Store, path string) (*ocispec.Descriptor, error) {
	dgst := digest.NewDigestFromEncoded(digest.SHA256, filepath.Base(path))
	if err := dgst.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid blob digest %q", filepath.Base(path))
	}

	desc, err := oci.IngestBlobFile(ctx, cs, path, dgst)
	if err != nil {
		return nil, err
	}
	desc.Annotations[nydus.LayerAnnotationNydusBlobOptimized] = "true"
	return &desc, nil
}

// writeOptimizedImage assembles the optimized manifest: the original data
// layers, the appended ondemand blob layer, and the rewritten bootstrap layer.
// The image config diff ids and history are updated accordingly.
func (o *Optimizer) writeOptimizedImage(ctx context.Context, cs content.Store, img *nydusfs.Image, ondemandDesc, bootstrapDesc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	// The source layout was validated when the image was parsed: data blobs,
	// optionally a previous ondemand blob, and the bootstrap last. Every data
	// layer is reused as-is; the bootstrap is replaced by the rewritten one. A
	// previous ondemand blob is kept because the rewritten bootstrap may still
	// reference it.
	blobs, _, prevOndemand, err := nydus.SplitLayers(img.Manifest.Layers)
	if err != nil {
		return nil, errors.Wrap(err, "split source layers")
	}
	dataLayers := blobs
	if prevOndemand != nil {
		dataLayers = append(dataLayers, *prevOndemand)
	}

	layers := make([]ocispec.Descriptor, 0, len(dataLayers)+2)
	diffIDs := make([]digest.Digest, 0, len(dataLayers)+2)
	for i, layer := range dataLayers {
		layers = append(layers, layer)
		if uncompressed := layer.Annotations[nydus.LayerAnnotationUncompressed]; uncompressed != "" {
			diffIDs = append(diffIDs, digest.Digest(uncompressed))
		} else if i < len(img.Config.RootFS.DiffIDs) {
			// Data layers from other builders may lack the uncompressed
			// annotation; keep the original diff id from the source config
			// (data layers and config diff ids are index-aligned, since the
			// bootstrap is the last layer).
			diffIDs = append(diffIDs, img.Config.RootFS.DiffIDs[i])
		} else {
			return nil, errors.Errorf("cannot determine diff id for layer %s", layer.Digest)
		}
	}
	for _, l := range []ocispec.Descriptor{ondemandDesc, bootstrapDesc} {
		uncompressed := l.Annotations[nydus.LayerAnnotationUncompressed]
		if uncompressed == "" {
			return nil, errors.Errorf("missing uncompressed annotation on appended layer %s", l.Digest)
		}
		diffIDs = append(diffIDs, digest.Digest(uncompressed))
	}
	layers = append(layers, ondemandDesc, bootstrapDesc)

	config := img.Config
	config.RootFS.DiffIDs = diffIDs
	config.History = append(config.History, ocispec.History{
		CreatedBy: "Nydus Optimizer",
		Comment:   "Nydus Ondemand Blob Layer",
	})

	configLabels := map[string]string{}
	newConfigDesc, err := oci.WriteJSON(ctx, cs, config, img.Manifest.Config, configLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write image config")
	}
	newConfigDesc.MediaType = ocispec.MediaTypeImageConfig

	manifest := img.Manifest
	manifest.Config = *newConfigDesc
	manifest.Layers = layers

	// Set gc labels so the referenced content is retained in the local store
	// until the push completes.
	manifestLabels := map[string]string{
		"containerd.io/gc.ref.content.config": newConfigDesc.Digest.String(),
	}
	for idx, l := range layers {
		manifestLabels["containerd.io/gc.ref.content.l."+strconv.Itoa(idx)] = l.Digest.String()
	}

	newManifestDesc, err := oci.WriteJSON(ctx, cs, manifest, img.Desc, manifestLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	newManifestDesc.Platform = img.Desc.Platform
	return newManifestDesc, nil
}
