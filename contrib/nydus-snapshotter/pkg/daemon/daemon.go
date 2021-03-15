/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package daemon

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk/model"
)

const (
	APISocketFileName   = "api.sock"
	SharedNydusDaemonID = "shared_daemon"
)

type NewDaemonOpt func(d *Daemon) error

type Daemon struct {
	ID             string
	SnapshotID     string
	ConfigDir      string
	SocketDir      string
	LogDir         string
	CacheDir       string
	SnapshotDir    string
	Pid            int
	client         nydussdk.Interface
	ImageID        string
	SharedDaemon   bool
	ApiSock        *string
	RootMountPoint *string
	mu             sync.Mutex
}

func (d *Daemon) SharedMountPoint() string {
	return filepath.Join(*d.RootMountPoint, d.SnapshotID, "fs")
}

func (d *Daemon) MountPoint() string {
	if d.RootMountPoint != nil {
		return filepath.Join("/", d.SnapshotID, "fs")
	}
	return filepath.Join(d.SnapshotDir, d.SnapshotID, "fs")
}

func (d *Daemon) BootstrapFile() (string, error) {
	// for backward compatibility check meta file from legacy location
	bootstrap := filepath.Join(d.SnapshotDir, d.SnapshotID, "fs", "image", "image.boot")
	_, err := os.Stat(bootstrap)
	if err == nil {
		return bootstrap, nil
	}
	if os.IsNotExist(err) {
		// meta file has been changed to <snapshotid>/fs/image.boot
		bootstrap = filepath.Join(d.SnapshotDir, d.SnapshotID, "fs", "image.boot")
		_, err = os.Stat(bootstrap)
		if err == nil {
			return bootstrap, nil
		}
	}
	return "", errors.Wrap(err, "failed to find bootstrap file")
}

func (d *Daemon) ConfigFile() string {
	return filepath.Join(d.ConfigDir, "config.json")
}

func (d *Daemon) APISock() string {
	if d.ApiSock != nil {
		return *d.ApiSock
	}
	return filepath.Join(d.SocketDir, APISocketFileName)
}

func (d *Daemon) LogFile() string {
	return filepath.Join(d.LogDir, "stderr.log")
}

func (d *Daemon) binary() string {
	return "/bin/nydusd"
}

func (d *Daemon) CheckStatus() (model.DaemonInfo, error) {
	client, err := nydussdk.NewNydusClient(d.APISock())
	if err != nil {
		return model.DaemonInfo{}, errors.Wrap(err, "failed to check status, client has not been initialized")
	}
	return client.CheckStatus()
}

func (d *Daemon) SharedMount() error {
	client, err := nydussdk.NewNydusClient(d.APISock())
	if err != nil {
		return errors.Wrap(err, "failed to mount")
	}
	bootstrap, err := d.BootstrapFile()
	if err != nil {
		return err
	}
	return client.SharedMount(d.MountPoint(), bootstrap, d.ConfigFile())
}

func (d *Daemon) SharedUmount() error {
	client, err := nydussdk.NewNydusClient(d.APISock())
	if err != nil {
		return errors.Wrap(err, "failed to mount")
	}
	return client.Umount(d.MountPoint())
}

func NewDaemon(opt ...NewDaemonOpt) (*Daemon, error) {
	d := &Daemon{Pid: 0}
	d.ID = newID()
	for _, o := range opt {
		err := o(d)
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}
