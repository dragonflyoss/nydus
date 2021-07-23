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

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

// ManifestRule validates manifest format of Nydus image
type ManifestRule struct {
	SourceParsed  *parser.Parsed
	TargetParsed  *parser.Parsed
	MultiPlatform bool
	BackendType   string
	ExpectedArch  string
}

func (rule *ManifestRule) Name() string {
	return "Manifest"
}

func (rule *ManifestRule) Validate() error {
	logrus.Infof("Checking Nydus manifest")

	// Ensure the target image represents a manifest list,
	// and it should consist of OCI and Nydus manifest
	if rule.MultiPlatform {
		if rule.TargetParsed.Index == nil {
			return errors.New("not found image manifest list")
		}
		foundNydusDesc := false
		foundOCIDesc := false
		for _, desc := range rule.TargetParsed.Index.Manifests {
			if desc.Platform == nil {
				continue
			}
			if desc.Platform.Architecture == rule.ExpectedArch && desc.Platform.OS == "linux" {
				if utils.IsNydusPlatform(desc.Platform) {
					foundNydusDesc = true
				} else {
					foundOCIDesc = true
				}
			}
		}
		if !foundNydusDesc {
			return errors.Errorf("not found nydus image of specified platform linux/%s", rule.ExpectedArch)
		}
		if !foundOCIDesc {
			return errors.Errorf("not found OCI image of specified platform linux/%s", rule.ExpectedArch)
		}
	}

	// Check manifest of Nydus
	if rule.TargetParsed.NydusImage == nil {
		return errors.New("invalid nydus image manifest")
	}

	layers := rule.TargetParsed.NydusImage.Manifest.Layers
	blobListInAnnotation := []string{}
	blobListInLayer := []string{}
	for i, layer := range layers {
		if i == len(layers)-1 {
			if layer.Annotations[utils.LayerAnnotationNydusBootstrap] != "true" {
				return errors.New("invalid bootstrap layer in nydus image manifest")
			}
			// Check blob list in annotation
			blobListStr, ok := layer.Annotations[utils.LayerAnnotationNydusBlobIDs]
			if !ok {
				return errors.New("invalid blob list in annotation of nydus image manifest")
			}
			if err := json.Unmarshal([]byte(blobListStr), &blobListInAnnotation); err != nil {
				return errors.Wrap(err, "failed to unmarshal blob list in annotation of nydus image manifest")
			}
		} else {
			if layer.MediaType != utils.MediaTypeNydusBlob ||
				layer.Annotations[utils.LayerAnnotationNydusBlob] != "true" {
				return errors.New("invalid blob layer in nydus image manifest")
			}
			blobListInLayer = append(blobListInLayer, layer.Digest.Hex())
		}
	}

	// Compare the blob list differences between bootstrap layer annotation
	// and manifest layers.
	if rule.BackendType == "registry" && !reflect.DeepEqual(blobListInAnnotation, blobListInLayer) {
		return fmt.Errorf(
			"unmatched blob list between in annotation and layers: %v != %v",
			blobListInAnnotation, blobListInLayer,
		)
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
