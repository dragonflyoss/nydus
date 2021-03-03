// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"reflect"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/pkg/checker/parser"
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
	if rule.TargetParsed.NydusManifest == nil {
		return errors.New("invalid nydus image manifest")
	}

	// Check image config of Nydus, and compare with OCI image
	if rule.TargetParsed.NydusConfig == nil {
		return errors.New("invalid nydus image config")
	}
	if rule.SourceParsed.OCIConfig != nil {
		ociConfig, err := json.Marshal(rule.SourceParsed.OCIConfig.Config)
		if err != nil {
			return errors.New("marshal oci image config")
		}
		nydusConfig, err := json.Marshal(rule.TargetParsed.NydusConfig.Config)
		if err != nil {
			return errors.New("marshal nydus image config")
		}
		if !reflect.DeepEqual(ociConfig, nydusConfig) {
			return errors.New("nydus image config should be equal with oci image config")
		}
	}

	// Check bootstrap layer exists
	if rule.TargetParsed.NydusBootstrap == nil {
		return errors.New("invalid bootstrap layer in nydus image")
	}

	return nil
}
