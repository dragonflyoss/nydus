/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package process

import (
	"context"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/store"
)

type Store interface {
	Get(id string) (*daemon.Daemon, error)
	GetBySnapshot(snapshotID string) (*daemon.Daemon, error)
	Add(*daemon.Daemon) error
	Delete(*daemon.Daemon) error
	List() []*daemon.Daemon
	Size() int
	WalkDaemons(ctx context.Context, cb func(*daemon.Daemon) error) error
	CleanupDaemons(ctx context.Context) error
}

var _ Store = &store.DaemonStore{}
