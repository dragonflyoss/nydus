// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/rule"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
)

// Opt defines Checker options.
// Note: target is the Nydus image reference.
type Opt struct {
	WorkDir        string
	Source         string
	Target         string
	SourceInsecure bool
	TargetInsecure bool
	MultiPlatform  bool
	NydusImagePath string
	NydusdPath     string
	BackendType    string
	BackendConfig  string
	ExpectedArch   string
}

// Checker validates Nydus image manifest, bootstrap and mounts filesystem
// by Nydusd to compare file metadata and data with OCI image.
type Checker struct {
	Opt
	sourceParser *parser.Parser
	targetParser *parser.Parser
}

// New creates Checker instance, target is the Nydus image reference.
func New(opt Opt) (*Checker, error) {
	// TODO: support source and target resolver
	targetRemote, err := provider.DefaultRemote(opt.Target, opt.TargetInsecure)
	if err != nil {
		return nil, errors.Wrap(err, "Init target image parser")
	}
	targetParser, err := parser.New(targetRemote, opt.ExpectedArch)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create parser")
	}

	var sourceParser *parser.Parser
	if opt.Source != "" {
		sourceRemote, err := provider.DefaultRemote(opt.Source, opt.SourceInsecure)
		if err != nil {
			return nil, errors.Wrap(err, "Init source image parser")
		}
		sourceParser, err = parser.New(sourceRemote, opt.ExpectedArch)
		if sourceParser == nil {
			return nil, errors.Wrap(err, "failed to create parser")
		}
	}

	checker := &Checker{
		Opt:          opt,
		sourceParser: sourceParser,
		targetParser: targetParser,
	}

	return checker, nil
}

// Check checks Nydus image, and outputs image information to work
// directory, the check workflow is composed of various rules.
func (checker *Checker) Check(ctx context.Context) error {
	targetParsed, err := checker.targetParser.Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "parse Nydus image")
	}

	var sourceParsed *parser.Parsed
	if checker.sourceParser != nil {
		sourceParsed, err = checker.sourceParser.Parse(ctx)
		if err != nil {
			return errors.Wrap(err, "parse source image")
		}
	} else {
		sourceParsed = targetParsed
	}

	if err := os.RemoveAll(checker.WorkDir); err != nil {
		return errors.Wrap(err, "clean up work directory")
	}

	if err := os.MkdirAll(filepath.Join(checker.WorkDir, "fs"), 0755); err != nil {
		return errors.Wrap(err, "create work directory")
	}

	if err := checker.Output(ctx, sourceParsed, targetParsed, checker.WorkDir); err != nil {
		return errors.Wrap(err, "output image information")
	}

	rules := []rule.Rule{
		&rule.ManifestRule{
			SourceParsed:  sourceParsed,
			TargetParsed:  targetParsed,
			MultiPlatform: checker.MultiPlatform,
			BackendType:   checker.BackendType,
			ExpectedArch:  checker.ExpectedArch,
		},
		&rule.BootstrapRule{
			Parsed:          targetParsed,
			NydusImagePath:  checker.NydusImagePath,
			BootstrapPath:   filepath.Join(checker.WorkDir, "nydus_bootstrap"),
			DebugOutputPath: filepath.Join(checker.WorkDir, "nydus_bootstrap_debug.json"),
		},
		&rule.FilesystemRule{
			Source:          checker.Source,
			SourceMountPath: filepath.Join(checker.WorkDir, "fs/source_mounted"),
			NydusdConfig: tool.NydusdConfig{
				NydusdPath:    checker.NydusdPath,
				BackendType:   checker.BackendType,
				BackendConfig: checker.BackendConfig,
				BootstrapPath: filepath.Join(checker.WorkDir, "nydus_bootstrap"),
				ConfigPath:    filepath.Join(checker.WorkDir, "fs/nydusd_config.json"),
				BlobCacheDir:  filepath.Join(checker.WorkDir, "fs/nydus_blobs"),
				MountPath:     filepath.Join(checker.WorkDir, "fs/nydus_mounted"),
				APISockPath:   filepath.Join(checker.WorkDir, "fs/nydus_api.sock"),
			},
		},
	}

	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return errors.Wrapf(err, "validate rule %s", rule.Name())
		}
	}

	logrus.Infof("Verified Nydus image %s", checker.targetParser.Remote.Ref)

	return nil
}
