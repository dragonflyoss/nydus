/*
 * Copyright (c) 2021. Alibaba Cloud. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
)

type FSMode int

const (
	SingleInstance FSMode = iota
	MultiInstance
	NoneInstance
)

type FileSystem interface {
	Mount(ctx context.Context, snapshotID string, labels map[string]string) error
	WaitUntilReady(ctx context.Context, snapshotID string) error
	Umount(ctx context.Context, mountPoint string) error
	Cleanup(ctx context.Context) error
	Support(ctx context.Context, labels map[string]string) bool
	PrepareLayer(ctx context.Context, snapshot storage.Snapshot, labels map[string]string) error
	MountPoint(snapshotID string) (string, error)
	BootstrapFile(snapshotID string) (string, error)
	NewDaemonConfig(labels map[string]string) (config.DaemonConfig, error)
}
