// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/nydus-snapshotter/pkg/label"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

// BootstrapRule validates bootstrap in nydus image
type BootstrapRule struct {
	WorkDir        string
	NydusImagePath string

	SourceParsed        *parser.Parsed
	TargetParsed        *parser.Parsed
	SourceBackendType   string
	SourceBackendConfig string
	TargetBackendType   string
	TargetBackendConfig string
}

type output struct {
	Blobs []string `json:"blobs"`
}

func (rule *BootstrapRule) Name() string {
	return "bootstrap"
}

func (rule *BootstrapRule) validate(parsed *parser.Parsed, dir string) error {
	if parsed == nil || parsed.NydusImage == nil {
		return nil
	}

	logrus.WithField("type", tool.CheckImageType(parsed)).WithField("image", parsed.Remote.Ref).Info("checking bootstrap")

	bootstrapDir := filepath.Join(rule.WorkDir, dir, "nydus_bootstrap")
	outputPath := filepath.Join(rule.WorkDir, dir, "nydus_output.json")

	// Get blob list in the blob table of bootstrap by calling
	// `nydus-image check` command
	builder := tool.NewBuilder(rule.NydusImagePath)
	if err := builder.Check(tool.BuilderOption{
		BootstrapPath:   filepath.Join(bootstrapDir, utils.BootstrapFileNameInLayer),
		DebugOutputPath: outputPath,
	}); err != nil {
		return errors.Wrap(err, "invalid nydus bootstrap format")
	}

	// Parse blob list from blob layers in nydus manifest
	blobListInLayer := map[string]bool{}
	layers := parsed.NydusImage.Manifest.Layers
	for i, layer := range layers {
		if layer.Annotations != nil && layers[i].Annotations[label.NydusRefLayer] != "" {
			// Ignore OCI reference layer check
			continue
		}
		if i != len(layers)-1 {
			blobListInLayer[layer.Digest.Hex()] = true
		}
	}

	// Parse blob list from blob table of bootstrap
	var out output
	outputBytes, err := os.ReadFile(outputPath)
	if err != nil {
		return errors.Wrap(err, "read bootstrap debug json")
	}
	if err := json.Unmarshal(outputBytes, &out); err != nil {
		return errors.Wrap(err, "unmarshal bootstrap output JSON")
	}
	blobListInBootstrap := map[string]bool{}
	lostInLayer := false
	for _, blobID := range out.Blobs {
		blobListInBootstrap[blobID] = true
		if !blobListInLayer[blobID] {
			lostInLayer = true
		}
	}

	if len(blobListInLayer) == 0 || !lostInLayer {
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

func (rule *BootstrapRule) Validate() error {
	if err := rule.validate(rule.SourceParsed, "source"); err != nil {
		return errors.Wrap(err, "source image: invalid nydus bootstrap")
	}

	if err := rule.validate(rule.TargetParsed, "target"); err != nil {
		return errors.Wrap(err, "target image: invalid nydus bootstrap")
	}

	return nil
}
