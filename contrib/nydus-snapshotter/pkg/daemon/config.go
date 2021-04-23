/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package daemon

import (
	"os"
	"path/filepath"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/pkg/errors"
)

func WithSnapshotID(id string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.SnapshotID = id
		return nil
	}
}

func WithID(id string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.ID = id
		return nil
	}
}

func WithConfigDir(dir string) NewDaemonOpt {
	return func(d *Daemon) error {
		s := filepath.Join(dir, d.ID)
		// this may be failed, should handle that
		if err := os.MkdirAll(s, 0755); err != nil {
			return errors.Wrapf(err, "failed to create config dir %s", s)
		}
		d.ConfigDir = s
		return nil
	}
}

func WithSocketDir(dir string) NewDaemonOpt {
	return func(d *Daemon) error {
		s := filepath.Join(dir, d.ID)
		// this may be failed, should handle that
		if err := os.MkdirAll(s, 0755); err != nil {
			return errors.Wrapf(err, "failed to create socket dir %s", s)
		}
		d.SocketDir = s
		return nil
	}
}

func WithLogDir(dir string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.LogDir = filepath.Join(dir, d.ID)
		return nil
	}
}

func WithCacheDir(dir string) NewDaemonOpt {
	return func(d *Daemon) error {
		// this may be failed, should handle that
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.Wrapf(err, "failed to create cache dir %s", dir)
		}
		d.CacheDir = dir
		return nil
	}
}

func WithRootMountPoint(rootMountPoint string) NewDaemonOpt {
	return func(d *Daemon) error {
		if err := os.MkdirAll(rootMountPoint, 0755); err != nil {
			return errors.Wrapf(err, "failed to create rootMountPoint %s", rootMountPoint)
		}
		d.RootMountPoint = &rootMountPoint
		return nil
	}
}


func WithSnapshotDir(dir string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.SnapshotDir = dir
		return nil
	}
}

func WithImageID(imageID string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.ImageID = imageID
		return nil
	}
}

func WithSharedDaemon() NewDaemonOpt {
	return func(d *Daemon) error {
		d.DaemonMode = config.DaemonModeShared
		return nil
	}
}

func WithAPISock(apiSock string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.ApiSock = &apiSock
		return nil
	}
}
