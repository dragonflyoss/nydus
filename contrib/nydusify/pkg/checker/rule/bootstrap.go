// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
)

// BootstrapRule validates bootstrap in Nydus image
type BootstrapRule struct {
	Parsed          *parser.Parsed
	BootstrapPath   string
	NydusImagePath  string
	DebugOutputPath string
	BackendType     string
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

	// For registry garbage collection, nydus puts the blobs to
	// the layers in manifest, so here only need to check blob
	// list consistency for registry backend.
	if rule.BackendType != "registry" {
		return nil
	}

	// Parse blob list from blob layers in Nydus manifest
	blobListInLayer := map[string]bool{}
	layers := rule.Parsed.NydusImage.Manifest.Layers
	for i, layer := range layers {
		if i != len(layers)-1 {
			blobListInLayer[layer.Digest.Hex()] = true
		}
	}

	// Parse blob list from blob table of bootstrap
	var bootstrap bootstrapDebug
	bootstrapBytes, err := os.ReadFile(rule.DebugOutputPath)
	if err != nil {
		return errors.Wrap(err, "read bootstrap debug json")
	}
	if err := json.Unmarshal(bootstrapBytes, &bootstrap); err != nil {
		return errors.Wrap(err, "unmarshal bootstrap output JSON")
	}
	blobListInBootstrap := map[string]bool{}
	lostInLayer := false
	for _, blobID := range bootstrap.Blobs {
		blobListInBootstrap[blobID] = true
		if !blobListInLayer[blobID] {
			lostInLayer = true
		}
	}

	if !lostInLayer {
		return nil
	}

	// The blobs recorded in blob table of bootstrap should all appear
	// in the layers.
	return fmt.Errorf(
		"nydus blobs in the blob table of bootstrap(%d) should all appear in the layers of manifest(%d), %v != %v",
		len(blobListInBootstrap),
		len(blobListInLayer),
		blobListInBootstrap,
		blobListInLayer,
	)
}
