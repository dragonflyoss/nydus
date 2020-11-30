/*
 * Copyright (c) 2020. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/pkg/errors"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/daemon"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/errdefs"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/filesystem/meta"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/label"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/process"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/signature"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/utils/retry"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/snapshot"
)

type filesystem struct {
	meta.FileSystemMeta
	manager          *process.Manager
	verifier         *signature.Verifier
	daemonCfg        DaemonConfig
	vpcRegistry      bool
	nydusdBinaryPath string
}

// NewFileSystem initialize Filesystem instance
func NewFileSystem(opt ...NewFSOpt) (snapshot.FileSystem, error) {
	var fs filesystem
	for _, o := range opt {
		err := o(&fs)
		if err != nil {
			return nil, err
		}
	}
	fs.manager = process.NewManager(process.Opt{
		NydusdBinaryPath: fs.nydusdBinaryPath,
	})
	return &fs, nil
}

func (fs *filesystem) Support(ctx context.Context, labels map[string]string) bool {
	_, ok := labels[label.NydusDataLayer]
	return ok
}

func (fs *filesystem) PrepareLayer(context.Context, storage.Snapshot, map[string]string) error {
	panic("implement me")
}

// Mount will be called when containerd snapshotter prepare remote snapshotter
// this method will fork nydus daemon and manage it in the internal store, and indexed by snapshotID
func (fs *filesystem) Mount(ctx context.Context, snapshotID string, labels map[string]string, sharedDaemon *daemon.Daemon) (err error) {
	imageID, ok := labels[label.ImageRef]
	if !ok {
		return fmt.Errorf("failed to find image ref of snapshot %s, labels %v", snapshotID, labels)
	}
	d, err := fs.createNewDaemon(snapshotID, imageID, sharedDaemon)
	// if daemon already exists for snapshotID, just return
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	defer func() {
		if err != nil {
			_ = fs.manager.DestroyDaemon(d)
		}
	}()
	// if publicKey is not empty we should verify bootstrap file of image
	bootstrap, err := d.BootstrapFile()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to find bootstrap file of daemon %s", d.ID))
	}
	err = fs.verifier.Verify(labels, bootstrap)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to verify signature of daemon %s", d.ID))
	}
	err = fs.manager.StartDaemon(d, fs.generateDaemonConfig(labels))
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed start daemon %s", d.ID))
	}
	return nil
}

// WaitUntilReady wait until daemon ready by snapshotID
func (fs *filesystem) WaitUntilReady(ctx context.Context, snapshotID string) error {
	s, err := fs.manager.GetBySnapshotID(snapshotID)
	if err != nil {
		return err
	}
	return retry.Do(func() error {
		info, err := s.CheckStatus()
		if err != nil {
			return err
		}
		log.G(ctx).Infof("daemon %s snapshotID %s info %v", s.ID, snapshotID, info)
		if info.State != "Running" {
			return errors.Wrap(err, fmt.Sprintf("daemon %s snapshotID %s is not ready", s.ID, snapshotID))
		}
		return nil
	},
		retry.Attempts(3),
		retry.LastErrorOnly(true),
		retry.Delay(100*time.Millisecond),
	)
}

func (fs *filesystem) Umount(ctx context.Context, mountPoint string) error {
	id := filepath.Base(mountPoint)
	return fs.manager.DestroyBySnapshotID(id)
}

func (fs *filesystem) Cleanup(ctx context.Context) error {
	for _, d := range fs.manager.ListDaemons() {
		err := fs.Umount(ctx, filepath.Dir(d.MountPoint()))
		if err != nil {
			log.G(ctx).Infof("failed to umount %s err %+v", d.MountPoint(), err)
		}
	}
	return nil
}

func (fs *filesystem) MountPoint(snapshotID string) (string, error) {
	if d, err := fs.manager.GetBySnapshotID(snapshotID); err != nil {
		return "", err
	} else {
		return d.MountPoint(), nil
	}
}

// createNewDaemon create new nydus daemon by snapshotID and imageID
func (fs *filesystem) createNewDaemon(snapshotID string, imageID string, sharedDaemon *daemon.Daemon) (*daemon.Daemon, error) {
	d, err := daemon.NewDaemon(
		daemon.WithSnapshotID(snapshotID),
		daemon.WithSocketDir(fs.SocketRoot()),
		daemon.WithConfigDir(fs.ConfigRoot()),
		daemon.WithSnapshotDir(fs.SnapshotRoot()),
		daemon.WithLogDir(fs.LogRoot()),
		daemon.WithCacheDir(fs.CacheRoot()),
		daemon.WithImageID(imageID),
		daemon.WithSharedDaemon(sharedDaemon),
	)
	if err != nil {
		return nil, err
	}
	err = fs.manager.NewDaemon(d)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// generateDaemonConfig generate Daemon configuration
func (fs *filesystem) generateDaemonConfig(labels map[string]string) func(*daemon.Daemon) error {
	return func(d *daemon.Daemon) error {
		cfg, err := NewDaemonConfig(fs.daemonCfg, d, fs.vpcRegistry, labels)
		if err != nil {
			return errors.Wrapf(err, "failed to generate daemon config for daemon %s", d.ID)
		}
		return SaveConfig(cfg, d.ConfigFile())
	}
}
