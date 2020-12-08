/*
 * Copyright (c) 2020. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package daemon

import (
	"fmt"
	"os"
	"path/filepath"

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
		s := filepath.Join(dir, d.ID)
		// this may be failed, should handle that
		if err := os.MkdirAll(s, 0755); err != nil {
			return errors.Wrapf(err, "failed to create log dir %s", s)
		}
		logs, err := prepareDaemonLogs(s)
		if err != nil {
			return errors.Wrap(err, "failed to prepare logs")
		}
		d.LogDir = s
		d.Stdout = logs[0]
		d.Stderr = logs[1]
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
		d.SharedDaemon = true
		return nil
	}
}

func WithAPISock(apiSock string) NewDaemonOpt {
	return func(d *Daemon) error {
		d.apiSock = &apiSock
		return nil
	}
}


func prepareDaemonLogs(logDir string) ([]*os.File, error) {
	var (
		err      error
		logFiles = make([]*os.File, 2)
	)
	for i, logName := range []string{"stdout.log", "stderr.log"} {
		logPath := filepath.Join(logDir, logName)
		logFiles[i], err = os.Create(logPath)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to create logfile %s", logPath))
		}
	}
	return logFiles, nil
}

