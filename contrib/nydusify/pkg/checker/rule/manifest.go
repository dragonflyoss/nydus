// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"reflect"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/pkg/parser"
	"contrib/nydusify/pkg/utils"
)

// ManifestRule validates manifest format of Nydus image
type ManifestRule struct {
	SourceParsed *parser.Parsed
	TargetParsed *parser.Parsed
}

func (rule *ManifestRule) Name() string {
	return "Manifest"
}

func (rule *ManifestRule) Validate() error {
	logrus.Infof("Checking Nydus manifest")

	// Check manifest of Nydus
	if rule.TargetParsed.NydusImage == nil {
		return errors.New("invalid nydus image manifest")
	}

	layers := rule.TargetParsed.NydusImage.Manifest.Layers
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

	// Check Nydus image config with OCI image
	if rule.SourceParsed.OCIImage != nil {
		ociConfig, err := json.Marshal(rule.SourceParsed.OCIImage.Config.Config)
		if err != nil {
			return errors.New("marshal oci image config")
		}
		nydusConfig, err := json.Marshal(rule.TargetParsed.NydusImage.Config.Config)
		if err != nil {
			return errors.New("marshal nydus image config")
		}
		if !reflect.DeepEqual(ociConfig, nydusConfig) {
			return errors.New("nydus image config should be equal with oci image config")
		}
	}

	return nil
}
