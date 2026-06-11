/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/lepton/leptonify/internal/converter"
	"github.com/dragonflyoss/lepton/leptonify/internal/remote"
)

// OptimizeOpt configures an Optimizer.
type OptimizeOpt struct {
	// Source is the lepton image reference to optimize. Required.
	Source string
	// Target is the optimized lepton image reference to push. Required.
	Target string
	// Apiserver is the apiserver address of a running mount of the source
	// image (e.g. `unix:///path/to/apiserver.sock`, as exposed by `leptonify
	// mount`); the access patterns are fetched live from its `/trace`
	// endpoint. Required.
	Apiserver string
	// Builder is the lepton binary path (PATH-resolvable). Defaults to "lepton".
	Builder string
	// WorkDir is the scratch directory backing the content store and the
	// optimize staging area. It must already exist.
	WorkDir string
	// Insecure skips TLS certificate verification for the registry.
	Insecure bool
	// PlainHTTP uses plain HTTP to talk to the registry.
	PlainHTTP bool
	// LogLevel is the log level forwarded to the `lepton` subprocess. Defaults
	// to "info" when empty.
	LogLevel string
	// PlatformMC selects which platform to optimize. Defaults to the host
	// platform.
	PlatformMC platforms.MatchComparer
}

// Optimizer builds an "ondemand" blob from a recorded group access pattern and
// publishes an optimized copy of a lepton image: the original data layers are
// reused as-is, an ondemand blob layer is appended, and the bootstrap layer is
// rewritten so the runtime prefetches the ondemand blob first.
type Optimizer struct {
	opt OptimizeOpt
}

// NewOptimizer creates an Optimizer.
func NewOptimizer(opt OptimizeOpt) (*Optimizer, error) {
	if opt.Source == "" {
		return nil, errors.New("source must be provided")
	}
	if opt.Target == "" {
		return nil, errors.New("target must be provided")
	}
	if opt.Apiserver == "" {
		return nil, errors.New("apiserver must be provided")
	}
	// Accept a bare socket path for convenience; lepton expects unix://.
	if !strings.HasPrefix(opt.Apiserver, "unix://") {
		opt.Apiserver = "unix://" + opt.Apiserver
	}
	if opt.PlatformMC == nil {
		opt.PlatformMC = platforms.Default()
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "info"
	}
	return &Optimizer{opt: opt}, nil
}

// ondemandDigestPattern matches the `ondemand_blob_digest: <hex>` line printed
// by `lepton optimize`.
var ondemandDigestPattern = regexp.MustCompile(`ondemand_blob_digest:\s*([0-9a-f]{64})`)

// Optimize pulls the source lepton image, runs `lepton optimize` against its
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

	provider, err := remote.NewProvider(remote.Options{
		WorkDir:    contentDir,
		Insecure:   o.opt.Insecure,
		PlainHTTP:  o.opt.PlainHTTP,
		PlatformMC: o.opt.PlatformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}
	cs := provider.ContentStore()

	img, err := loadImage(ctx, provider, o.opt.Source, o.opt.PlatformMC)
	if err != nil {
		return errors.Wrapf(err, "load source %q", o.opt.Source)
	}
	if img.Kind != KindLepton {
		return errors.Errorf("source %q is not a lepton image", o.opt.Source)
	}
	if img.Bootstrap == nil {
		return errors.New("lepton image is missing its bootstrap layer")
	}

	stageDir, err := os.MkdirTemp(scratchDir, "optimize-")
	if err != nil {
		return errors.Wrap(err, "create optimize scratch dir")
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	// Extract the parent bootstrap and the per-layer blob metas, and seed the
	// cache dir with the metas so `lepton optimize` loads source metadata from
	// disk and only fetches group data ranges from the registry.
	bootDir := filepath.Join(stageDir, "bootstrap")
	bootstrapPath, blobMetaPaths, err := extractBootstrapLayer(ctx, cs, *img.Bootstrap, bootDir)
	if err != nil {
		return errors.Wrap(err, "extract bootstrap")
	}
	cacheDir := filepath.Join(stageDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return errors.Wrap(err, "create cache dir")
	}
	if err := linkBlobMetaFiles(ctx, blobMetaPaths, cacheDir); err != nil {
		return errors.Wrap(err, "link blob meta to cache")
	}

	configPath := filepath.Join(stageDir, "config.yaml")
	if _, err := writeRegistryConfig(provider, img, cacheDir, configPath, false); err != nil {
		return errors.Wrap(err, "generate storage config")
	}

	blobDir := filepath.Join(stageDir, "blobs")
	optimizedBootstrapPath := filepath.Join(stageDir, "image.boot.optimized")
	ondemandHex, err := o.runLeptonOptimize(ctx, bootstrapPath, optimizedBootstrapPath, blobDir, configPath)
	if err != nil {
		return err
	}
	log.G(ctx).Infof("built ondemand blob %s", ondemandHex)

	// Commit the ondemand blob as a lepton data layer.
	ondemandDesc, err := commitBlobFile(ctx, cs, filepath.Join(blobDir, ondemandHex))
	if err != nil {
		return errors.Wrap(err, "commit ondemand blob")
	}

	// Rebuild the bootstrap layer tar: the rewritten image.boot, the original
	// per-layer blob metas, and the ondemand blob meta.
	bootstrapData, err := os.ReadFile(optimizedBootstrapPath)
	if err != nil {
		return errors.Wrap(err, "read optimized bootstrap")
	}
	blobMetas := make([]converter.BlobMetaFile, 0, len(blobMetaPaths)+1)
	for _, p := range blobMetaPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return errors.Wrapf(err, "read blob meta %q", p)
		}
		blobMetas = append(blobMetas, converter.BlobMetaFile{Name: filepath.Base(p), Data: data})
	}
	ondemandMeta, err := os.ReadFile(filepath.Join(blobDir, ondemandHex+".blob.meta"))
	if err != nil {
		return errors.Wrap(err, "read ondemand blob meta")
	}
	blobMetas = append(blobMetas, converter.BlobMetaFile{Name: ondemandHex + ".blob.meta", Data: ondemandMeta})

	bootstrapDesc, err := converter.WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas)
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

// runLeptonOptimize invokes `lepton optimize` and returns the ondemand blob
// digest hex parsed from its output.
func (o *Optimizer) runLeptonOptimize(ctx context.Context, parentBootstrap, bootstrap, blobDir, configPath string) (string, error) {
	args := []string{
		"optimize",
		"--apiserver", o.opt.Apiserver,
		"--parent-bootstrap", parentBootstrap,
		"--bootstrap", bootstrap,
		"--blob-dir", blobDir,
		"--config", configPath,
		"--log-level", leptonLogLevel(o.opt.LogLevel),
	}
	cmd := exec.CommandContext(ctx, builderBinary(o.opt.Builder), args...)
	var output bytes.Buffer
	cmd.Stdout = io.MultiWriter(&output, os.Stderr)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", errors.Wrap(err, "run lepton optimize")
	}
	match := ondemandDigestPattern.FindSubmatch(output.Bytes())
	if match == nil {
		return "", errors.New("lepton optimize did not report an ondemand blob digest")
	}
	return string(match[1]), nil
}

// commitBlobFile commits a digest-named lepton blob file from disk into the
// content store as a lepton data layer descriptor.
func commitBlobFile(ctx context.Context, cs content.Store, path string) (*ocispec.Descriptor, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "open blob %q", path)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "stat blob")
	}
	dgst := digest.NewDigestFromEncoded(digest.SHA256, filepath.Base(path))
	if err := dgst.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid blob digest %q", filepath.Base(path))
	}

	cw, err := content.OpenWriter(ctx, cs, content.WithRef("lepton-ondemand-"+dgst.String()))
	if err != nil {
		return nil, errors.Wrap(err, "open blob writer")
	}
	defer func() { _ = cw.Close() }()
	if err := content.Copy(ctx, cw, file, info.Size(), dgst); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, errors.Wrap(err, "commit blob")
	}

	return &ocispec.Descriptor{
		MediaType: converter.MediaTypeLeptonBlob,
		Digest:    dgst,
		Size:      info.Size(),
		Annotations: map[string]string{
			// A lepton full blob is self-describing and uncompressed at the
			// layer level, so the diff id equals the blob digest.
			converter.LayerAnnotationUncompressed: dgst.String(),
			converter.LayerAnnotationLeptonBlob:   "true",
		},
	}, nil
}

// writeOptimizedImage assembles the optimized manifest: the original data
// layers, the appended ondemand blob layer, and the rewritten bootstrap layer.
// The image config diff ids and history are updated accordingly.
func (o *Optimizer) writeOptimizedImage(ctx context.Context, cs content.Store, img *Image, ondemandDesc, bootstrapDesc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	layers := make([]ocispec.Descriptor, 0, len(img.Manifest.Layers)+1)
	for _, layer := range img.Manifest.Layers {
		if converter.IsLeptonBootstrap(layer) {
			continue
		}
		layers = append(layers, layer)
	}
	layers = append(layers, ondemandDesc, bootstrapDesc)

	config := img.Config
	diffIDs := make([]digest.Digest, 0, len(layers))
	for _, l := range layers {
		if uncompressed := l.Annotations[converter.LayerAnnotationUncompressed]; uncompressed != "" {
			diffIDs = append(diffIDs, digest.Digest(uncompressed))
		}
	}
	config.RootFS.DiffIDs = diffIDs
	config.History = append(config.History, ocispec.History{
		CreatedBy: "Lepton Optimizer",
		Comment:   "Lepton Ondemand Blob Layer",
	})

	configLabels := map[string]string{}
	newConfigDesc, err := converter.WriteJSON(ctx, cs, config, img.Manifest.Config, configLabels)
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

	newManifestDesc, err := converter.WriteJSON(ctx, cs, manifest, img.Desc, manifestLabels)
	if err != nil {
		return nil, errors.Wrap(err, "write manifest")
	}
	newManifestDesc.Platform = img.Desc.Platform
	return newManifestDesc, nil
}
