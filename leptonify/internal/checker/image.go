/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"encoding/json"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/lepton/leptonify/internal/converter"
)

// ImageKind distinguishes a plain OCI image from a converted lepton image.
type ImageKind int

const (
	// KindOCI is a regular OCI image.
	KindOCI ImageKind = iota
	// KindLepton is a lepton (nydus-compatible) image with a bootstrap layer.
	KindLepton
)

func (k ImageKind) String() string {
	if k == KindLepton {
		return "lepton"
	}
	return "oci"
}

// Image is a parsed single-platform image (OCI or lepton) loaded from a content
// store.
type Image struct {
	// Ref is the original image reference.
	Ref string
	// Desc is the resolved manifest descriptor.
	Desc ocispec.Descriptor
	// Manifest is the image manifest.
	Manifest ocispec.Manifest
	// Config is the image config.
	Config ocispec.Image
	// Kind reports whether this is an OCI or lepton image.
	Kind ImageKind
	// Bootstrap is the lepton bootstrap layer (only set for KindLepton).
	Bootstrap *ocispec.Descriptor
	// Blobs are the lepton data blob layers (only set for KindLepton).
	Blobs []ocispec.Descriptor
}

// parseImage resolves rootDesc (a manifest or an index) into a single-platform
// Image, reading the manifest and config from cs and classifying the image as
// OCI or lepton.
func parseImage(ctx context.Context, cs content.Store, ref string, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (*Image, error) {
	manifestDesc, err := selectManifest(ctx, cs, rootDesc, platformMC)
	if err != nil {
		return nil, errors.Wrap(err, "select platform manifest")
	}

	var manifest ocispec.Manifest
	if err := readJSON(ctx, cs, manifestDesc, &manifest); err != nil {
		return nil, errors.Wrap(err, "read manifest")
	}

	var config ocispec.Image
	if err := readJSON(ctx, cs, manifest.Config, &config); err != nil {
		return nil, errors.Wrap(err, "read image config")
	}

	img := &Image{
		Ref:      ref,
		Desc:     manifestDesc,
		Manifest: manifest,
		Config:   config,
		Kind:     KindOCI,
	}

	// A lepton image carries a bootstrap layer (marked by annotation). The
	// remaining layers are lepton data blobs.
	for i := range manifest.Layers {
		layer := manifest.Layers[i]
		if converter.IsLeptonBootstrap(layer) {
			img.Kind = KindLepton
			bootstrap := layer
			img.Bootstrap = &bootstrap
			continue
		}
		if converter.IsLeptonBlob(layer) {
			img.Blobs = append(img.Blobs, layer)
		}
	}

	return img, nil
}

// selectManifest returns the manifest descriptor for the requested platform. If
// rootDesc is already a manifest it is returned as-is.
func selectManifest(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (ocispec.Descriptor, error) {
	if images.IsManifestType(rootDesc.MediaType) {
		return rootDesc, nil
	}
	if !images.IsIndexType(rootDesc.MediaType) {
		return ocispec.Descriptor{}, errors.Errorf("unsupported root media type %q", rootDesc.MediaType)
	}

	var index ocispec.Index
	if err := readJSON(ctx, cs, rootDesc, &index); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "read index")
	}
	if len(index.Manifests) == 0 {
		return ocispec.Descriptor{}, errors.New("image index has no manifests")
	}

	var candidates []ocispec.Descriptor
	for _, m := range index.Manifests {
		if !images.IsManifestType(m.MediaType) {
			continue
		}
		if m.Platform == nil || platformMC.Match(*m.Platform) {
			candidates = append(candidates, m)
		}
	}
	if len(candidates) == 0 {
		return ocispec.Descriptor{}, errors.New("no manifest matches the requested platform")
	}

	// Prefer the platform the matcher considers most specific.
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.Platform != nil && best.Platform != nil && platformMC.Less(*c.Platform, *best.Platform) {
			best = c
		}
	}
	return best, nil
}

// readJSON reads desc from cs and unmarshals it into v.
func readJSON(ctx context.Context, cs content.Store, desc ocispec.Descriptor, v interface{}) error {
	b, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return errors.Wrapf(err, "read blob %s", desc.Digest)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.Wrapf(err, "unmarshal %s", desc.Digest)
	}
	return nil
}
