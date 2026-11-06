/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
)

// CommittedBlobs returns the IDs of the blobs committed bootstraps reference.
func (s *snapshotter) CommittedBlobs(ctx context.Context) (map[string]struct{}, error) {
	var dirs []string
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return s.walkInfo(ctx, func(ctx context.Context, info snapshots.Info) error {
			if info.Kind != snapshots.KindCommitted || !labels(info.Labels).isNydusBootstrap() {
				return nil
			}

			id, _, _, err := storage.GetInfo(ctx, info.Name)
			if err != nil {
				return err
			}

			dirs = append(dirs, s.upperPath(id))
			return nil
		})
	}); err != nil {
		return nil, err
	}

	blobs := map[string]struct{}{}
	for _, dir := range dirs {
		// A bootstrap layer without a readable image dir never starts a
		// daemon, and must not stop GC of every other blob.
		ids, err := nydusfs.NewBootstrapLayer(dir).Blobs()
		if err != nil {
			log.G(ctx).WithError(err).WithField("path", dir).Warn("skip unreadable bootstrap layer")
			continue
		}

		for _, id := range ids {
			blobs[id] = struct{}{}
		}
	}

	return blobs, nil
}

// walkInfo walks the snapshots in the transaction of ctx. A fresh metastore
// has no snapshots bucket yet, which holds no snapshot.
func (s *snapshotter) walkInfo(ctx context.Context, fn snapshots.WalkFunc) error {
	if err := storage.WalkInfo(ctx, fn); err != nil && !errdefs.IsNotFound(err) {
		return err
	}

	return nil
}
