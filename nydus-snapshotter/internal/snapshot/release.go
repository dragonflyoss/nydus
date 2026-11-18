/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"time"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/log"
)

// releaseInterval is the interval of release passes besides removals, which
// also catches daemons that exited on their own.
const releaseInterval = time.Minute

// Run releases unused daemons on every removal and tick until ctx is done.
// The first pass reconciles what a restart or reboot left behind.
func (s *snapshotter) Run(ctx context.Context) {
	ticker := time.NewTicker(releaseInterval)
	defer ticker.Stop()

	for ctx.Err() == nil {
		// Bound a pass by the interval; what it leaves the next one picks up.
		// A pass that shutdown cut short is no failure.
		passCtx, cancel := context.WithTimeout(ctx, releaseInterval)
		if err := s.fileSystem.Release(passCtx, s.usedImages); err != nil && ctx.Err() == nil {
			log.G(ctx).WithError(err).Error("release unused daemons")
		}
		cancel()

		select {
		case <-ctx.Done():
		case <-s.release:
		case <-ticker.C:
		}
	}
}

// wakeRelease wakes the release worker without blocking.
func (s *snapshotter) wakeRelease() {
	select {
	case s.release <- struct{}{}:
	default:
	}
}

// usedImages returns the chain IDs of the bootstrap layers below any active
// or view snapshot, in every namespace. It walks the metastore once.
func (s *snapshotter) usedImages(ctx context.Context) (map[string]struct{}, error) {
	infos := map[string]snapshots.Info{}
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return s.walkInfo(ctx, func(_ context.Context, info snapshots.Info) error {
			infos[info.Name] = info
			return nil
		})
	}); err != nil {
		return nil, err
	}

	used := map[string]struct{}{}
	for _, info := range infos {
		if info.Kind == snapshots.KindCommitted {
			continue
		}

		// A parent that is gone is the zero info, which ends the chain.
		for name := info.Parent; name != ""; name = infos[name].Parent {
			if parent := infos[name]; labels(parent.Labels).isNydusBootstrap() {
				used[parent.Labels[labelSnapshotRef]] = struct{}{}
				break
			}
		}
	}

	return used, nil
}
