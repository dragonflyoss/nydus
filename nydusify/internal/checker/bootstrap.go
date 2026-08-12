/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package checker validates that a converted nydus image is faithful to its
// OCI source by comparing manifests, bootstrap metadata and the materialized
// root filesystem.
package checker

import (
	"bytes"
	"cmp"
	"context"
	"os"
	"os/exec"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// bootstrapRule validates each nydus image's bootstrap by running
// `nydus check` against the materialized bootstrap and its data blobs.
type bootstrapRule struct {
	cs      content.Store
	builder string
	workDir string
	source  *nydusfs.Image
	target  *nydusfs.Image
}

func (r *bootstrapRule) Name() string { return "bootstrap" }

func (r *bootstrapRule) Validate(ctx context.Context) error {
	if err := r.validateImage(ctx, "source", r.source); err != nil {
		return errors.Wrap(err, "source bootstrap")
	}
	if err := r.validateImage(ctx, "target", r.target); err != nil {
		return errors.Wrap(err, "target bootstrap")
	}
	return nil
}

// validateImage runs `nydus check` for a single image. OCI images (which have
// no bootstrap) are skipped. The check is purely static: only the bootstrap is
// materialized, so data blob layers (which are never pulled) are not required.
func (r *bootstrapRule) validateImage(ctx context.Context, label string, img *nydusfs.Image) error {
	if img == nil || img.Kind != nydusfs.KindNydus {
		return nil
	}
	if img.Bootstrap == nil {
		return errors.New("nydus image is missing its bootstrap layer")
	}

	dir, err := os.MkdirTemp(r.workDir, "bootstrap-"+label+"-")
	if err != nil {
		return errors.Wrap(err, "create scratch dir")
	}
	defer func() { _ = os.RemoveAll(dir) }()

	bootstrapPath, _, err := nydusfs.ExtractBootstrapLayer(ctx, r.cs, *img.Bootstrap, dir)
	if err != nil {
		return errors.Wrap(err, "extract bootstrap")
	}

	log.G(ctx).Debugf("statically checking %s bootstrap", label)
	if err := runNydusCheck(ctx, r.builder, bootstrapPath); err != nil {
		return err
	}
	return nil
}

// runNydusCheck invokes `nydus check` to statically validate a bootstrap.
// Data blobs are not verified, so no blob directory is required.
func runNydusCheck(ctx context.Context, builder, bootstrapPath string) error {
	args := []string{
		"check",
		"--bootstrap", bootstrapPath,
	}
	cmd := exec.CommandContext(ctx, cmp.Or(builder, nydus.DefaultBuilder), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus check failed: %s", stderr.String())
	}
	return nil
}
