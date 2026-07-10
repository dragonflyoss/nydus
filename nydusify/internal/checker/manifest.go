/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"reflect"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/converter"
)

// manifestRule validates the structural correctness of each image's manifest
// and, when both images are present, that their runtime configs are equivalent.
type manifestRule struct {
	source *Image
	target *Image
}

func (r *manifestRule) Name() string { return "manifest" }

func (r *manifestRule) Validate(_ context.Context) error {
	if err := validateImageManifest(r.source); err != nil {
		return errors.Wrap(err, "source manifest")
	}
	if err := validateImageManifest(r.target); err != nil {
		return errors.Wrap(err, "target manifest")
	}
	if r.source != nil && r.target != nil {
		if err := compareConfigs(r.source, r.target); err != nil {
			return errors.Wrap(err, "config consistency")
		}
	}
	return nil
}

// validateImageManifest checks layer/diff-id counts and nydus layer
// annotations for a single image.
func validateImageManifest(img *Image) error {
	if img == nil {
		return nil
	}
	if img.Kind == KindNydus {
		return validateNydusManifest(img)
	}
	return validateOCIManifest(img)
}

func validateOCIManifest(img *Image) error {
	if len(img.Manifest.Layers) != len(img.Config.RootFS.DiffIDs) {
		return errors.Errorf("layer count (%d) does not match diff id count (%d)",
			len(img.Manifest.Layers), len(img.Config.RootFS.DiffIDs))
	}
	return nil
}

func validateNydusManifest(img *Image) error {
	layers := img.Manifest.Layers
	if len(layers) == 0 {
		return errors.New("nydus image has no layers")
	}

	// The last layer must be the bootstrap; all preceding layers must be blobs.
	bootstrap := layers[len(layers)-1]
	if img.Bootstrap == nil || bootstrap.Digest != img.Bootstrap.Digest {
		return errors.New("the last layer is not a nydus bootstrap")
	}
	for _, layer := range layers[:len(layers)-1] {
		if !isNydusBlobLayer(layer) {
			return errors.Errorf("layer %s is neither a nydus blob nor the bootstrap", layer.Digest)
		}
	}
	if len(img.Manifest.Layers) != len(img.Config.RootFS.DiffIDs) {
		return errors.Errorf("layer count (%d) does not match diff id count (%d)",
			len(img.Manifest.Layers), len(img.Config.RootFS.DiffIDs))
	}
	return nil
}

func isNydusBlobLayer(layer ocispec.Descriptor) bool {
	if converter.IsNydusBlob(layer) {
		return true
	}
	if layer.Annotations == nil {
		return false
	}
	_, ok := layer.Annotations[converter.LayerAnnotationNydusBlob]
	return ok
}

// compareConfigs verifies that the runtime-relevant fields of the source and
// target configs are equivalent. The conversion only rewrites RootFS.DiffIDs
// and History, so the remaining config must be identical.
func compareConfigs(source, target *Image) error {
	if !reflect.DeepEqual(source.Config.Config, target.Config.Config) {
		return errors.New("image config (env/cmd/entrypoint/working dir/etc) differs between source and target")
	}
	if source.Config.OS != target.Config.OS {
		return errors.Errorf("os mismatch (source %q, target %q)", source.Config.OS, target.Config.OS)
	}
	if source.Config.Architecture != target.Config.Architecture {
		return errors.Errorf("architecture mismatch (source %q, target %q)", source.Config.Architecture, target.Config.Architecture)
	}
	return nil
}
