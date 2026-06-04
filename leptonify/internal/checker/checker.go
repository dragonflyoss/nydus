/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
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

	"github.com/dragonflyoss/lepton/leptonify/internal/remote"
)

// Opt configures a Checker.
type Opt struct {
	// Source is the source image reference (OCI or lepton). May be empty.
	Source string
	// Target is the target image reference (OCI or lepton). May be empty.
	Target string
	// Builder is the lepton binary path (PATH-resolvable). Defaults to "lepton".
	Builder string
	// WorkDir is the scratch directory backing the content store and rule
	// staging. It must already exist.
	WorkDir string
	// Insecure skips TLS certificate verification for the registry.
	Insecure bool
	// PlainHTTP uses plain HTTP to talk to the registry.
	PlainHTTP bool
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
		WorkDir:    contentDir,
		Insecure:   c.opt.Insecure,
		PlainHTTP:  c.opt.PlainHTTP,
		PlatformMC: c.opt.PlatformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}
	cs := provider.ContentStore()

	source, err := c.load(ctx, provider, c.opt.Source)
	if err != nil {
		return errors.Wrapf(err, "load source %q", c.opt.Source)
	}
	target, err := c.load(ctx, provider, c.opt.Target)
	if err != nil {
		return errors.Wrapf(err, "load target %q", c.opt.Target)
	}

	rules := []Rule{
		&manifestRule{source: source, target: target},
		&bootstrapRule{cs: cs, builder: c.opt.Builder, workDir: scratchDir, source: source, target: target},
		&filesystemRule{cs: cs, builder: c.opt.Builder, workDir: scratchDir, source: source, target: target},
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
func (c *Checker) load(ctx context.Context, provider *remote.Provider, ref string) (*Image, error) {
	if ref == "" {
		return nil, nil
	}
	log.G(ctx).Infof("pulling image %s", ref)
	desc, err := provider.Pull(ctx, ref)
	if err != nil {
		return nil, errors.Wrap(err, "pull")
	}
	img, err := parseImage(ctx, provider.ContentStore(), ref, desc, c.opt.PlatformMC)
	if err != nil {
		return nil, errors.Wrap(err, "parse")
	}
	log.G(ctx).Infof("parsed %s as a %s image", ref, img.Kind)
	return img, nil
}
