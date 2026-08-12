/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"context"
	"os"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
)

// ApplyOCIImage applies all OCI layers of img sequentially into rootfs,
// resolving whiteouts so the result is the fully merged root filesystem.
func ApplyOCIImage(ctx context.Context, cs content.Store, img *Image, rootfs string) error {
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return errors.Wrap(err, "create rootfs dir")
	}
	for _, layer := range img.Manifest.Layers {
		if err := applyOCILayer(ctx, cs, layer, rootfs); err != nil {
			return errors.Wrapf(err, "apply layer %s", layer.Digest)
		}
	}
	return nil
}

func applyOCILayer(ctx context.Context, cs content.Store, layer ocispec.Descriptor, rootfs string) error {
	decompressed, err := oci.OpenDecompressedBlob(ctx, cs, layer)
	if err != nil {
		return errors.Wrap(err, "open layer")
	}
	defer func() { _ = decompressed.Close() }()

	// Preserve the original uid/gid recorded in the layer so the comparison
	// reflects the real image ownership (requires root, enforced by the
	// filesystem rule's privilege precheck).
	if _, err := archive.Apply(ctx, rootfs, decompressed); err != nil {
		return errors.Wrap(err, "apply layer archive")
	}
	return nil
}
