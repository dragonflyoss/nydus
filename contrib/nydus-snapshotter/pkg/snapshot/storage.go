/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/pkg/errors"
)

type WalkFunc = func(snapshots.Info) bool

func GetSnapshotInfo(ctx context.Context, ms *storage.MetaStore, key string) (string, snapshots.Info, snapshots.Usage, error) {
	ctx, t, err := ms.TransactionContext(ctx, false)
	if err != nil {
		return "", snapshots.Info{}, snapshots.Usage{}, err
	}
	defer t.Rollback()
	id, info, usage, err := storage.GetInfo(ctx, key)
	if err != nil {
		return "", snapshots.Info{}, snapshots.Usage{}, err
	}

	return id, info, usage, nil
}

func GetSnapshot(ctx context.Context, ms *storage.MetaStore, key string) (*storage.Snapshot, error) {
	ctx, t, err := ms.TransactionContext(ctx, false)
	if err != nil {
		return nil, err
	}
	s, err := storage.GetSnapshot(ctx, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get active mount")
	}
	err = t.Rollback()
	if err != nil {
		return nil, errors.Wrap(err, "failed to rollback transaction")
	}
	return &s, nil
}

func FindSnapshot(ctx context.Context, ms *storage.MetaStore, key string, fn WalkFunc) (string, snapshots.Info, error) {
	ctx, t, err := ms.TransactionContext(ctx, false)
	if err != nil {
		return "", snapshots.Info{}, err
	}
	defer t.Rollback()
	for cKey := key; cKey != ""; {
		id, info, _, err := storage.GetInfo(ctx, cKey)
		if err != nil {
			log.G(ctx).WithError(err).Warnf("failed to get info of %q", cKey)
			return "", snapshots.Info{}, err
		}
		if fn(info) {
			return id, info, nil
		} else {
			log.G(ctx).Infof("id %s is data layer, continue to check parent layer", id)
		}
		cKey = info.Parent
	}
	return "", snapshots.Info{}, fmt.Errorf("failed to find meta layer of key %s", key)
}

func UpdateSnapshotInfo(ctx context.Context, ms *storage.MetaStore, info snapshots.Info, fieldPaths ...string) (snapshots.Info, error) {
	ctx, t, err := ms.TransactionContext(ctx, true)
	if err != nil {
		return snapshots.Info{}, err
	}
	info, err = storage.UpdateInfo(ctx, info, fieldPaths...)
	if err != nil {
		t.Rollback()
		return snapshots.Info{}, err
	}
	if err := t.Commit(); err != nil {
		return snapshots.Info{}, err
	}
	return info, nil
}
