/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"os"
	"path/filepath"

	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

// Opt configures a Checker.
type Opt struct {
	// Source is the source image reference (OCI or nydus). May be empty.
	Source string
	// Target is the target image reference (OCI or nydus). May be empty.
	Target string
	// Builder is the nydus binary path (PATH-resolvable). Defaults to "nydus".
	Builder string
	// WorkDir is the scratch directory backing the content store and rule
	// staging. It must already exist.
	WorkDir string
	// SourceInsecure skips TLS certificate verification for the source registry.
	SourceInsecure bool
	// SourcePlainHTTP uses plain HTTP to talk to the source registry.
	SourcePlainHTTP bool
	// TargetInsecure skips TLS certificate verification for the target registry.
	TargetInsecure bool
	// TargetPlainHTTP uses plain HTTP to talk to the target registry.
	TargetPlainHTTP bool
	// LogLevel is the log level forwarded to the `nydus` subprocesses
	// (trace/debug/info/warn/error). Defaults to "info" when empty.
	LogLevel string
	// PlatformMC selects which platform to check. Defaults to the host platform.
	PlatformMC platforms.MatchComparer
}

// Checker validates the consistency of a source/target image pair.
type Checker struct {
	opt Opt
}

// New creates a Checker.
func New(opt Opt) (*Checker, error) {
	if opt.Source == "" && opt.Target == "" {
		return nil, errors.New("at least one of source or target must be provided")
	}
	if opt.PlatformMC == nil {
		opt.PlatformMC = platforms.Default()
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "info"
	}
	return &Checker{opt: opt}, nil
}

// Check pulls the configured images, parses them, and runs the validation
// rules sequentially.
func (c *Checker) Check(ctx context.Context) error {
	contentDir := filepath.Join(c.opt.WorkDir, "content")
	scratchDir := filepath.Join(c.opt.WorkDir, "scratch")
	for _, d := range []string{contentDir, scratchDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %q", d)
		}
	}

	provider, err := remote.NewProvider(remote.Options{
		WorkDir:         contentDir,
		SourceInsecure:  c.opt.SourceInsecure,
		SourcePlainHTTP: c.opt.SourcePlainHTTP,
		TargetInsecure:  c.opt.TargetInsecure,
		TargetPlainHTTP: c.opt.TargetPlainHTTP,
		PlatformMC:      c.opt.PlatformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}
	cs := provider.ContentStore()

	// A filesystem diff only runs when both a source and a target image are
	// present. When only one is provided, OCI data layers are not needed and
	// are therefore not pulled. Nydus data blob layers are never pulled by the
	// checker: the bootstrap check is static and the FUSE mount fetches blobs on
	// demand from the registry.
	bothPresent := c.opt.Source != "" && c.opt.Target != ""
	pullOpts := remote.PullOptions{PullOCILayers: bothPresent, PullNydusBlobs: false}

	source, err := c.load(ctx, provider, c.opt.Source, pullOpts, remote.Source)
	if err != nil {
		return errors.Wrapf(err, "load source %q", c.opt.Source)
	}
	target, err := c.load(ctx, provider, c.opt.Target, pullOpts, remote.Target)
	if err != nil {
		return errors.Wrapf(err, "load target %q", c.opt.Target)
	}

	// When only a single image is checked, export its metadata (index,
	// manifest, config and, for nydus images, the bootstrap layer) into the
	// work directory for inspection.
	if !bothPresent {
		if source != nil {
			if err := exportImage(ctx, cs, source, filepath.Join(c.opt.WorkDir, "source")); err != nil {
				return errors.Wrap(err, "export source")
			}
		}
		if target != nil {
			if err := exportImage(ctx, cs, target, filepath.Join(c.opt.WorkDir, "target")); err != nil {
				return errors.Wrap(err, "export target")
			}
		}
	}

	rules := []Rule{
		&manifestRule{source: source, target: target},
		&bootstrapRule{cs: cs, builder: c.opt.Builder, workDir: scratchDir, source: source, target: target},
		&filesystemRule{cs: cs, provider: provider, builder: c.opt.Builder, logLevel: c.opt.LogLevel, workDir: scratchDir, source: source, target: target},
	}

	for _, rule := range rules {
		log.G(ctx).Infof("running %s rule", rule.Name())
		if err := rule.Validate(ctx); err != nil {
			return errors.Wrapf(err, "%s rule failed", rule.Name())
		}
	}

	log.G(ctx).Info("all checks passed")
	return nil
}

// load pulls and parses an image reference, returning nil for an empty ref.
func (c *Checker) load(ctx context.Context, provider *remote.Provider, ref string, pullOpts remote.PullOptions, reg remote.Registry) (*Image, error) {
	if ref == "" {
		return nil, nil
	}
	return loadImage(ctx, provider, ref, c.opt.PlatformMC, pullOpts, reg)
}
