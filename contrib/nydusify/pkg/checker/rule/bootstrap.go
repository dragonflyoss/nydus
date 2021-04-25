// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
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

	var blobListInAnnotation []string
	layers := rule.Parsed.NydusImage.Manifest.Layers

	// Parse blob list from bootstrap layer annotation in Nydus manifest
	blobListStr := rule.Parsed.NydusImage.Manifest.Layers[len(layers)-1].Annotations[utils.LayerAnnotationNydusBlobIDs]
	if blobListStr != "" {
		if err := json.Unmarshal([]byte(blobListStr), &blobListInAnnotation); err != nil {
			return errors.Wrap(err, "unmarshal blob list from layer annotation")
		}
	}

	// Blob list recorded in manifest annotation should be equal with
	// the blob list recorded in blob table of bootstrap
	if !reflect.DeepEqual(bootstrap.Blobs, blobListInAnnotation) {
		return fmt.Errorf(
			"nydus blob list in bootstrap(%d) does not match with manifest(%d)'s",
			len(bootstrap.Blobs),
			len(blobListInAnnotation),
		)
	}

	return nil
}
