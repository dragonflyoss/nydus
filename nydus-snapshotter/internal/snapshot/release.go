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

// releaseInterval is the interval of teardown passes besides removals, which
// also catches daemons that exited on their own.
const releaseInterval = time.Minute

// Run tears down unused daemons on every removal and tick until ctx is done.
// The first pass reconciles what a restart or reboot left behind.
func (s *snapshotter) Run(ctx context.Context) {
	ticker := time.NewTicker(releaseInterval)
	defer ticker.Stop()

	for {
		// Bound a pass by the interval; what it leaves the next one picks up.
		passCtx, cancel := context.WithTimeout(ctx, releaseInterval)
		s.releaseAll(passCtx)
		cancel()

		select {
		case <-ctx.Done():
			return
		case <-s.release:
		case <-ticker.C:
		}
	}
}

// releaseAll releases the unused daemons of every file system.
func (s *snapshotter) releaseAll(ctx context.Context) {
	for version, fileSystem := range s.fileSystems {
		if err := fileSystem.Release(ctx, s.usedImages); err != nil {
			log.G(ctx).WithError(err).WithField("fs_version", version).Error("release unused daemons")
		}
	}
}

// usedImages returns the chain IDs of the bootstraps an active or view
// snapshot of any namespace stands on, from one metastore walk.
func (s *snapshotter) usedImages(ctx context.Context) (map[string]struct{}, error) {
	used := map[string]struct{}{}
	err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		infos := map[string]snapshots.Info{}
		if err := s.walkInfo(ctx, func(_ context.Context, info snapshots.Info) error {
			infos[info.Name] = info
			return nil
		}); err != nil {
			return err
		}

		for _, info := range infos {
			if info.Kind == snapshots.KindCommitted {
				continue
			}

			for name := info.Parent; name != ""; {
				parent, ok := infos[name]
				if !ok {
					break
				}

				if labels(parent.Labels).isNydusBootstrap() {
					used[parent.Labels[labelSnapshotRef]] = struct{}{}
					break
				}

				name = parent.Parent
			}
		}

		return nil
	})

	return used, err
}
