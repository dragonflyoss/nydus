/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package nydusfs holds the shared plumbing for materializing a pulled image
// locally: loading and classifying an image (OCI or nydus), extracting the
// nydus bootstrap layer and its blob meta artifacts, applying OCI layers into
// a rootfs, and generating the registry-backed storage config consumed by the
// `nydus` binary. It is shared by the check, mount and optimize commands.
package nydusfs

import (
	"context"
	"slices"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// ImageKind distinguishes a plain OCI image from a converted nydus image.
type ImageKind int

const (
	// KindOCI is a regular OCI image.
	KindOCI ImageKind = iota
	// KindNydus is a nydus (nydus-compatible) image with a bootstrap layer.
	KindNydus
)

func (k ImageKind) String() string {
	if k == KindNydus {
		return "nydus"
	}
	return "oci"
}

// Image is a parsed single-platform image (OCI or nydus) loaded from a content
// store.
type Image struct {
	// Ref is the original image reference.
	Ref string
	// Root is the resolved root descriptor (an image index or, for a
	// single-platform reference, the manifest itself).
	Root ocispec.Descriptor
	// Desc is the resolved manifest descriptor.
	Desc ocispec.Descriptor
	// Manifest is the image manifest.
	Manifest ocispec.Manifest
	// Config is the image config.
	Config ocispec.Image
	// Kind reports whether this is an OCI or nydus image.
	Kind ImageKind
	// Bootstrap is the nydus bootstrap layer (only set for KindNydus).
	Bootstrap *ocispec.Descriptor
}

// LoadImage pulls ref through provider and parses it into a single-platform
// Image. The reference must be non-empty. pullOpt selects which data layers
// are downloaded. reg selects which registry side's TLS/HTTP settings to use.
func LoadImage(ctx context.Context, provider *remote.Provider, ref string, platformMC platforms.MatchComparer, pullOpt remote.PullOption, reg remote.Side) (*Image, error) {
	log.G(ctx).Infof("pulling image %s", ref)
	desc, err := provider.Pull(ctx, ref, pullOpt, reg)
	if err != nil {
		return nil, errors.Wrap(err, "pull")
	}
	img, err := parseImage(ctx, provider.ContentStore(), ref, desc, platformMC)
	if err != nil {
		return nil, errors.Wrap(err, "parse")
	}
	log.G(ctx).Infof("parsed %s as a %s image", ref, img.Kind)
	return img, nil
}

// parseImage resolves rootDesc (a manifest or an index) into a single-platform
// Image, reading the manifest and config from cs and classifying the image as
// OCI or nydus.
func parseImage(ctx context.Context, cs content.Store, ref string, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (*Image, error) {
	manifestDesc, err := oci.ResolveManifest(ctx, cs, rootDesc, platformMC)
	if err != nil {
		return nil, errors.Wrap(err, "select platform manifest")
	}

	var manifest ocispec.Manifest
	if err := oci.ReadJSON(ctx, cs, manifestDesc, &manifest); err != nil {
		return nil, errors.Wrap(err, "read manifest")
	}

	var config ocispec.Image
	if err := oci.ReadJSON(ctx, cs, manifest.Config, &config); err != nil {
		return nil, errors.Wrap(err, "read image config")
	}

	img := &Image{
		Ref:      ref,
		Root:     rootDesc,
		Desc:     manifestDesc,
		Manifest: manifest,
		Config:   config,
		Kind:     KindOCI,
	}

	// A nydus image is marked by its bootstrap layer (annotated, canonically
	// last). When one is present the whole layer list must follow the
	// canonical nydus layout, which also pins down the bootstrap descriptor.
	if slices.ContainsFunc(manifest.Layers, nydus.IsBootstrap) {
		_, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
		if err != nil {
			return nil, errors.Wrap(err, "invalid nydus image layers")
		}
		img.Kind = KindNydus
		img.Bootstrap = bootstrap
	}

	return img, nil
}
