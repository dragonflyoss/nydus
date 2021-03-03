// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package provider abstract interface to adapt to different build environments,
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"contrib/nydusify/pkg/utils"
)

const defaultOS = "linux"
const defaultArch = "amd64"

// SourceLayer is a layer of source image
type SourceLayer interface {
	Mount(ctx context.Context) (string, func() error, error)
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
	image   v1.Image
}

type defaultSourceLayer struct {
	mountDir      string
	layer         v1.Layer
	digest        digest.Digest
	size          int64
	chainID       digest.Digest
	parentChainID *digest.Digest
}

func withDefaultAuth() authn.Keychain {
	return authn.DefaultKeychain
}

func (sp *defaultSourceProvider) Manifest(ctx context.Context) (*ocispec.Descriptor, error) {
	size, err := sp.image.Size()
	if err != nil {
		return nil, errors.Wrap(err, "Get source image manifest size")
	}

	mediaType, err := sp.image.MediaType()
	if err != nil {
		return nil, errors.Wrap(err, "Get source image manifest media type")
	}

	_digest, err := sp.image.Digest()
	if err != nil {
		return nil, errors.Wrap(err, "Get source image manifest digest")
	}

	return &ocispec.Descriptor{
		Size:      size,
		MediaType: string(mediaType),
		Digest:    digest.Digest(_digest.String()),
	}, nil
}

func (sp *defaultSourceProvider) Config(ctx context.Context) (*ocispec.Image, error) {
	configBytes, err := sp.image.RawConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "Get source image config")
	}

	var config ocispec.Image
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, errors.Wrap(err, "Unmarshal source image config")
	}

	return &config, nil
}

func (sp *defaultSourceProvider) Layers(ctx context.Context) ([]SourceLayer, error) {
	layers, err := sp.image.Layers()
	if err != nil {
		return nil, err
	}

	var parentChainID *digest.Digest
	diffIDs := []digest.Digest{}
	sourceLayers := []SourceLayer{}

	for _, _layer := range layers {
		diffID, err := _layer.DiffID()
		if err != nil {
			return nil, errors.Wrap(err, "Get source layer DiffID")
		}
		layerDigest, err := _layer.Digest()
		if err != nil {
			return nil, errors.Wrap(err, "Get source layer digest")
		}
		size, err := _layer.Size()
		if err != nil {
			return nil, errors.Wrap(err, "Get source layer size")
		}
		diffIDs = append(diffIDs, digest.Digest(diffID.String()))
		chainID := identity.ChainID(diffIDs)
		layer := &defaultSourceLayer{
			mountDir:      filepath.Join(sp.workDir, layerDigest.String()),
			layer:         _layer,
			digest:        digest.Digest(layerDigest.String()),
			size:          size,
			chainID:       chainID,
			parentChainID: parentChainID,
		}
		sourceLayers = append(sourceLayers, layer)
		parentChainID = &chainID
	}

	return sourceLayers, nil
}

func (sl *defaultSourceLayer) Mount(ctx context.Context) (string, func() error, error) {
	digestStr := sl.digest.String()

	// Pull the layer from source, we need to retry in case of
	// the layer is compressed or uncompressed
	reader, err := sl.layer.Compressed()
	if err != nil {
		reader, err = sl.layer.Uncompressed()
		if err != nil {
			return "", nil, errors.Wrap(err, fmt.Sprintf("Decompress source layer %s", digestStr))
		}
		defer reader.Close()
	}
	defer reader.Close()

	// Decompress layer from source stream
	if err := utils.UnpackTargz(ctx, sl.mountDir, reader); err != nil {
		return "", nil, errors.Wrap(err, fmt.Sprintf("Decompress source layer %s", digestStr))
	}

	umount := func() error {
		return os.RemoveAll(sl.mountDir)
	}

	return sl.mountDir, umount, nil
}

func (sl *defaultSourceLayer) Digest() digest.Digest {
	return sl.digest
}

func (sl *defaultSourceLayer) Size() int64 {
	return sl.size
}

func (sl *defaultSourceLayer) ChainID() digest.Digest {
	return sl.chainID
}

func (sl *defaultSourceLayer) ParentChainID() *digest.Digest {
	return sl.parentChainID
}

// DefaultSource pulls image layers from specify image reference
func DefaultSource(ref string, insecure bool, workDir string) (SourceProvider, error) {
	sourceOpts := []name.Option{}
	if insecure {
		sourceOpts = append(sourceOpts, name.Insecure)
	}
	sourceRef, err := name.ParseReference(ref, sourceOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "Parse source reference")
	}

	image, err := remote.Image(
		sourceRef,
		remote.WithAuthFromKeychain(withDefaultAuth()),
		remote.WithPlatform(v1.Platform{
			Architecture: defaultArch,
			OS:           defaultOS,
		}),
	)
	if err != nil {
		return nil, errors.Wrap(err, "Fetch source image")
	}

	sp := defaultSourceProvider{
		workDir: workDir,
		image:   image,
	}

	return &sp, nil
}
