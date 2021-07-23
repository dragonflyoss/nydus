// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package provider abstracts interface to adapt to different build environments,
// the provider includes these components:
// 	logger: output build progress for nydusify or buildkitd/buildctl;
// 	remote: create a remote resolver, it communicates with remote registry;
// 	source: responsible for getting image manifest, config, and mounting layer;
// Provider provides a default implementation, so we can use it in Nydusify
// directly, but we need to implement it in buildkit or other any projects
// which want to import nydusify package.
package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/mount"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

// SourceLayer is a layer of source image
type SourceLayer interface {
	Mount(ctx context.Context) ([]mount.Mount, func() error, error)
	Size() int64
	Digest() digest.Digest
	ChainID() digest.Digest
	ParentChainID() *digest.Digest
}

// SourceProvider provides resource of source image
type SourceProvider interface {
	Manifest(ctx context.Context) (*ocispec.Descriptor, error)
	Config(ctx context.Context) (*ocispec.Image, error)
	Layers(ctx context.Context) ([]SourceLayer, error)
}

type defaultSourceProvider struct {
	workDir string
	image   parser.Image
	remote  *remote.Remote
}

type defaultSourceLayer struct {
	remote        *remote.Remote
	mountDir      string
	desc          ocispec.Descriptor
	chainID       digest.Digest
	parentChainID *digest.Digest
}

func (sp *defaultSourceProvider) Manifest(ctx context.Context) (*ocispec.Descriptor, error) {
	return &sp.image.Desc, nil
}

func (sp *defaultSourceProvider) Config(ctx context.Context) (*ocispec.Image, error) {
	return &sp.image.Config, nil
}

func (sp *defaultSourceProvider) Layers(ctx context.Context) ([]SourceLayer, error) {
	layers := sp.image.Manifest.Layers
	diffIDs := sp.image.Config.RootFS.DiffIDs
	if len(layers) != len(diffIDs) {
		return nil, fmt.Errorf("Mismatched fs layers (%d) and diff ids (%d)", len(layers), len(diffIDs))
	}

	var parentChainID *digest.Digest
	sourceLayers := []SourceLayer{}

	for i, desc := range layers {
		chainID := identity.ChainID(diffIDs[:i+1])
		layer := &defaultSourceLayer{
			remote: sp.remote,
			// Use layer ChainID as the mounted directory name, in case of
			// the layers in the same Digest are removed by umount.
			mountDir:      filepath.Join(sp.workDir, chainID.String()),
			desc:          desc,
			chainID:       chainID,
			parentChainID: parentChainID,
		}
		sourceLayers = append(sourceLayers, layer)
		parentChainID = &chainID
	}

	return sourceLayers, nil
}

func (sl *defaultSourceLayer) Mount(ctx context.Context) ([]mount.Mount, func() error, error) {
	digestStr := sl.desc.Digest.String()

	if err := utils.WithRetry(func() error {
		// Pull the layer from source
		reader, err := sl.remote.Pull(ctx, sl.desc, true)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("Decompress source layer %s", digestStr))
		}
		defer reader.Close()

		// Decompress layer from source stream
		if err := utils.UnpackTargz(ctx, sl.mountDir, reader); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Decompress source layer %s", digestStr))
		}

		return nil
	}); err != nil {
		return nil, nil, err
	}

	umount := func() error {
		return os.RemoveAll(sl.mountDir)
	}

	mounts := []mount.Mount{
		{
			Type:   "oci-directory",
			Source: sl.mountDir,
		},
	}

	return mounts, umount, nil
}

func (sl *defaultSourceLayer) Digest() digest.Digest {
	return sl.desc.Digest
}

func (sl *defaultSourceLayer) Size() int64 {
	return sl.desc.Size
}

func (sl *defaultSourceLayer) ChainID() digest.Digest {
	return sl.chainID
}

func (sl *defaultSourceLayer) ParentChainID() *digest.Digest {
	return sl.parentChainID
}

// Input platform string should be formated like os/arch.
func ExtractOsArch(platform string) (string, string, error) {

	if len(strings.Split(platform, "/")) != 2 {
		return "", "", fmt.Errorf("invalid platform format, %s", platform)
	}

	p := strings.Split(platform, "/")
	os := p[0]
	arch := p[1]

	if os != "linux" {
		return "", "", fmt.Errorf("not support os %s", os)
	}

	if !utils.IsSupportedArch(arch) {
		return "", "", fmt.Errorf("not support architecture %s", arch)
	}

	return os, arch, nil
}

// DefaultSource pulls image layers from specify image reference
func DefaultSource(ctx context.Context, remote *remote.Remote, workDir, platform string) ([]SourceProvider, error) {

	_, arch, err := ExtractOsArch(platform)
	if err != nil {
		return nil, err
	}

	parser, err := parser.New(remote, arch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create parser")
	}
	parsed, err := parser.Parse(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Parse source image")
	}

	if parsed.OCIImage == nil {
		if parsed.NydusImage != nil {
			return nil, fmt.Errorf("the source is an image that only included Nydus manifest")
		}
		return nil, fmt.Errorf("not found OCI %s manifest in source image", utils.SupportedOS+"/"+utils.SupportedArch)
	}

	sp := []SourceProvider{
		&defaultSourceProvider{
			workDir: workDir,
			image:   *parsed.OCIImage,
			remote:  remote,
		},
	}

	return sp, nil
}
