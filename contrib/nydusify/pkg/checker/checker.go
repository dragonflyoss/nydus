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

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/rule"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

// Opt defines Checker options.
// Note: target is the nydus image reference.
type Opt struct {
	WorkDir string

	Source              string
	Target              string
	SourceInsecure      bool
	TargetInsecure      bool
	SourceBackendType   string
	SourceBackendConfig string
	TargetBackendType   string
	TargetBackendConfig string

	MultiPlatform  bool
	NydusImagePath string
	NydusdPath     string
	ExpectedArch   string
}

// Checker validates nydus image manifest, bootstrap and mounts filesystem
// by nydusd to compare file metadata and data between OCI / nydus image.
type Checker struct {
	Opt
	sourceParser *parser.Parser
	targetParser *parser.Parser
}

// New creates Checker instance, target is the nydus image reference.
func New(opt Opt) (*Checker, error) {
	targetRemote, err := provider.DefaultRemote(opt.Target, opt.TargetInsecure)
	if err != nil {
		return nil, errors.Wrap(err, "init target image parser")
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
		if err != nil {
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

// Check checks nydus image, and outputs image information to work
// directory, the check workflow is composed of various rules.
func (checker *Checker) Check(ctx context.Context) error {
	if err := checker.check(ctx); err != nil {
		if utils.RetryWithHTTP(err) {
			if checker.sourceParser != nil {
				checker.sourceParser.Remote.MaybeWithHTTP(err)
			}
			checker.targetParser.Remote.MaybeWithHTTP(err)
			return checker.check(ctx)
		}
		return err
	}
	return nil
}

// Check checks nydus image, and outputs image information to work
// directory, the check workflow is composed of various rules.
func (checker *Checker) check(ctx context.Context) error {
	logrus.WithField("image", checker.targetParser.Remote.Ref).Infof("parsing image")
	targetParsed, err := checker.targetParser.Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "parse nydus image")
	}

	var sourceParsed *parser.Parsed
	if checker.sourceParser != nil {
		sourceParsed, err = checker.sourceParser.Parse(ctx)
		if err != nil {
			return errors.Wrap(err, "parse source image")
		}
	}

	if err := os.RemoveAll(checker.WorkDir); err != nil {
		return errors.Wrap(err, "clean up work directory")
	}

	if sourceParsed != nil {
		if err := checker.Output(ctx, sourceParsed, filepath.Join(checker.WorkDir, "source")); err != nil {
			return errors.Wrapf(err, "output image information: %s", sourceParsed.Remote.Ref)
		}
	}

	if targetParsed != nil {
		if err := checker.Output(ctx, targetParsed, filepath.Join(checker.WorkDir, "target")); err != nil {
			return errors.Wrapf(err, "output image information: %s", targetParsed.Remote.Ref)
		}
	}

	rules := []rule.Rule{
		&rule.ManifestRule{
			SourceParsed: sourceParsed,
			TargetParsed: targetParsed,
		},
		&rule.BootstrapRule{
			WorkDir:        checker.WorkDir,
			NydusImagePath: checker.NydusImagePath,

			SourceParsed:        sourceParsed,
			TargetParsed:        targetParsed,
			SourceBackendType:   checker.SourceBackendType,
			SourceBackendConfig: checker.SourceBackendConfig,
			TargetBackendType:   checker.TargetBackendType,
			TargetBackendConfig: checker.TargetBackendConfig,
		},
		&rule.FilesystemRule{
			WorkDir:    checker.WorkDir,
			NydusdPath: checker.NydusdPath,

			SourceImage: &rule.Image{
				Parsed:   sourceParsed,
				Insecure: checker.SourceInsecure,
			},
			TargetImage: &rule.Image{
				Parsed:   targetParsed,
				Insecure: checker.TargetInsecure,
			},
			SourceBackendType:   checker.SourceBackendType,
			SourceBackendConfig: checker.SourceBackendConfig,
			TargetBackendType:   checker.TargetBackendType,
			TargetBackendConfig: checker.TargetBackendConfig,
		},
	}

	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return errors.Wrapf(err, "validate %s failed", rule.Name())
		}
	}

	logrus.Info("verified image")

	return nil
}
