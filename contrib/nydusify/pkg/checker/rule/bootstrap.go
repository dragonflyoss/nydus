// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"io/ioutil"
	"reflect"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/checker/parser"
	"contrib/nydusify/checker/tool"
	"contrib/nydusify/utils"
)

// BootstrapRule validates bootstrap in Nydus image
type BootstrapRule struct {
	Parsed          *parser.Parsed
	BootstrapPath   string
	NydusImagePath  string
	DebugOutputPath string
}

type bootstrapDebug struct {
	Blobs []string `json:"blobs"`
}

func (rule *BootstrapRule) Name() string {
	return "Bootstrap"
}

func (rule *BootstrapRule) Validate() error {
	logrus.Infof("Checking Nydus bootstrap")

	// Get blob list in the blob table of bootstrap by calling
	// `nydus-image check` command
	builder := tool.NewBuilder(rule.NydusImagePath)
	if err := builder.Check(tool.BuilderOption{
		BootstrapPath:   rule.BootstrapPath,
		DebugOutputPath: rule.DebugOutputPath,
	}); err != nil {
		return errors.Wrap(err, "invalid nydus bootstrap format")
	}

	var bootstrap bootstrapDebug
	bootstrapBytes, err := ioutil.ReadFile(rule.DebugOutputPath)
	if err != nil {
		return errors.Wrap(err, "read bootstrap debug json")
	}
	if err := json.Unmarshal(bootstrapBytes, &bootstrap); err != nil {
		return errors.Wrap(err, "unmarshal bootstrap output JSON")
	}

	var blobIDs []string
	// Parse blob list from layers in Nydus manifest
	layers := rule.Parsed.NydusManifest.Layers
	if len(layers) > 1 {
		for _, layer := range layers[:len(layers)-1] {
			blobIDs = append(blobIDs, layer.Digest.Hex())
		}
	}
	// Parse blob list from bootstrap layer annotation in Nydus manifest
	if len(blobIDs) == 0 {
		blobIDStr := rule.Parsed.NydusManifest.Layers[len(layers)-1].Annotations[utils.LayerAnnotationNydusBlobIDs]
		if blobIDStr != "" {
			if err := json.Unmarshal([]byte(blobIDStr), &blobIDs); err != nil {
				return errors.Wrap(err, "unmarshal blob ids from layer annotation")
			}
		}
	}
	// Blob list recorded in manifest should be equal with the blob table of bootstrap
	if !reflect.DeepEqual(bootstrap.Blobs, blobIDs) {
		logrus.Warnf(
			"nydus blob list in bootstrap(%d) is not match with manifest(%d)",
			len(bootstrap.Blobs),
			len(blobIDs),
		)
	}

	return nil
}
