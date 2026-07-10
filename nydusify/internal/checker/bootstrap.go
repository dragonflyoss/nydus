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
	"context"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/pkg/errors"
)

// bootstrapRule validates each nydus image's bootstrap by running
// `nydus check` against the materialized bootstrap and its data blobs.
type bootstrapRule struct {
	cs      content.Store
	builder string
	workDir string
	source  *Image
	target  *Image
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
func (r *bootstrapRule) validateImage(ctx context.Context, label string, img *Image) error {
	if img == nil || img.Kind != KindNydus {
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

	bootstrapPath := filepath.Join(dir, "image.boot")
	if err := extractBootstrap(ctx, r.cs, *img.Bootstrap, bootstrapPath); err != nil {
		return errors.Wrap(err, "extract bootstrap")
	}

	log.G(ctx).Debugf("statically checking %s bootstrap", label)
	if err := runNydusCheck(ctx, r.builder, bootstrapPath); err != nil {
		return err
	}
	return nil
}
