/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"fmt"
	"slices"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/errdefs"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
)

// NydusImage returns the nydus image whose committed bootstrap layer has one
// of chainIDs, the chain IDs of an image's layers. The caller sets its
// reference.
func (s *snapshotter) NydusImage(ctx context.Context, chainIDs []string) (*nydusfs.Image, error) {
	var image *nydusfs.Image
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return s.walkInfo(ctx, func(ctx context.Context, info snapshots.Info) error {
			bootstrapLabels := labels(info.Labels)
			chainID := bootstrapLabels[labelSnapshotRef]
			if image != nil || info.Kind != snapshots.KindCommitted || !bootstrapLabels.isNydusBootstrap() || !slices.Contains(chainIDs, chainID) {
				return nil
			}

			if err := bootstrapLabels.validateFSVersion(); err != nil {
				return err
			}

			id, _, _, err := storage.GetInfo(ctx, info.Name)
			if err != nil {
				return err
			}

			image = &nydusfs.Image{ChainID: chainID, BootstrapDir: s.upperPath(id)}
			return nil
		})
	}); err != nil {
		return nil, err
	}

	if image == nil {
		return nil, fmt.Errorf("no layer of the image is a nydus bootstrap layer this snapshotter unpacked: %w", errdefs.ErrNotFound)
	}

	return image, nil
}
