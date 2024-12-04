// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

// ManifestRule validates manifest format of nydus image
type ManifestRule struct {
	SourceParsed *parser.Parsed
	TargetParsed *parser.Parsed
}

func (rule *ManifestRule) Name() string {
	return "manifest"
}

func (rule *ManifestRule) validateConfig(sourceImage, targetImage *parser.Image) error {
	//nolint:staticcheck
	// ignore static check SA1019 here. We have to assign deprecated field.
	//
	// Skip ArgsEscaped's Check
	//
	//   This field is present only for legacy compatibility with Docker and
	// should not be used by new image builders. Nydusify (1.6 and above)
	// ignores it, which is an expected behavior.
	//   Also ignore it in check.
	//
	//   Addition: [ArgsEscaped in spec](https://github.com/opencontainers/image-spec/pull/892)
	sourceImage.Config.Config.ArgsEscaped = targetImage.Config.Config.ArgsEscaped

	sourceConfig, err := json.Marshal(sourceImage.Config.Config)
	if err != nil {
		return errors.New("marshal source image config")
	}
	targetConfig, err := json.Marshal(targetImage.Config.Config)
	if err != nil {
		return errors.New("marshal target image config")
	}
	if !reflect.DeepEqual(sourceConfig, targetConfig) {
		return errors.New("source image config should be equal with target image config")
	}

	return nil
}

func (rule *ManifestRule) validateOCI(image *parser.Image) error {
	// Check config diff IDs
	layers := image.Manifest.Layers
	if len(image.Config.RootFS.DiffIDs) != len(layers) {
		return fmt.Errorf("invalid diff ids in image config: %d (diff ids) != %d (layers)", len(image.Config.RootFS.DiffIDs), len(layers))
	}

	return nil
}

func (rule *ManifestRule) validateNydus(image *parser.Image) error {
	// Check bootstrap and blob layers
	layers := image.Manifest.Layers
	for i, layer := range layers {
		if i == len(layers)-1 {
			if layer.Annotations[utils.LayerAnnotationNydusBootstrap] != "true" {
				return errors.New("invalid bootstrap layer in nydus image manifest")
			}
		} else {
			if layer.MediaType != utils.MediaTypeNydusBlob ||
				layer.Annotations[utils.LayerAnnotationNydusBlob] != "true" {
				return errors.New("invalid blob layer in nydus image manifest")
			}
		}
	}

	// Check config diff IDs
	if len(image.Config.RootFS.DiffIDs) != len(layers) {
		return fmt.Errorf("invalid diff ids in image config: %d (diff ids) != %d (layers)", len(image.Config.RootFS.DiffIDs), len(layers))
	}

	return nil
}

func (rule *ManifestRule) validate(parsed *parser.Parsed) error {
	if parsed == nil {
		return nil
	}

	logrus.WithField("type", tool.CheckImageType(parsed)).WithField("image", parsed.Remote.Ref).Infof("checking manifest")
	if parsed.OCIImage != nil {
		return errors.Wrap(rule.validateOCI(parsed.OCIImage), "invalid OCI image manifest")
	} else if parsed.NydusImage != nil {
		return errors.Wrap(rule.validateNydus(parsed.NydusImage), "invalid nydus image manifest")
	}

	return errors.New("not found valid image")
}

func (rule *ManifestRule) Validate() error {
	if err := rule.validate(rule.SourceParsed); err != nil {
		return errors.Wrap(err, "source image: invalid manifest")
	}

	if err := rule.validate(rule.TargetParsed); err != nil {
		return errors.Wrap(err, "target image: invalid manifest")
	}

	if rule.SourceParsed != nil && rule.TargetParsed != nil {
		sourceImage := rule.SourceParsed.OCIImage
		if sourceImage == nil {
			sourceImage = rule.SourceParsed.NydusImage
		}
		targetImage := rule.TargetParsed.OCIImage
		if targetImage == nil {
			targetImage = rule.TargetParsed.NydusImage
		}
		if err := rule.validateConfig(sourceImage, targetImage); err != nil {
			return fmt.Errorf("validate image config: %v", err)
		}
	}

	return nil
}
