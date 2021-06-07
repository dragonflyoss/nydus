/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/cache"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/errdefs"
	fspkg "github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/meta"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/label"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/signature"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/retry"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

type filesystem struct {
	meta.FileSystemMeta
	manager          *process.Manager
	cacheMgr         *cache.Manager
	verifier         *signature.Verifier
	daemonCfg        config.DaemonConfig
	vpcRegistry      bool
	nydusdBinaryPath string
	mode             fspkg.FSMode
}

// NewFileSystem initialize Filesystem instance
func NewFileSystem(ctx context.Context, opt ...NewFSOpt) (_ fspkg.FileSystem, retErr error) {
	var fs filesystem
	for _, o := range opt {
		err := o(&fs)
		if err != nil {
			return nil, err
		}
	}

	// Try to reconnect to running daemons
	if err := fs.manager.Reconnect(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to reconnect daemons")
	}

	if fs.mode == fspkg.SingleInstance {
		// Check if daemon is already running
		d, err := fs.manager.GetByID(daemon.SharedNydusDaemonID)
		if err == nil && d != nil {
			log.G(ctx).Infof("daemon(ID=%s) is already running and reconnected", daemon.SharedNydusDaemonID)
			return &fs, nil
		}

		d, err = fs.newSharedDaemon()
		if err != nil {
			return nil, errors.Wrap(err, "failed to init shared daemon")
		}

		defer func() {
			if retErr != nil {
				fs.manager.DeleteDaemon(d)
			}
		}()
		if err := fs.manager.StartDaemon(d); err != nil {
			return nil, errors.Wrap(err, "failed to start shared daemon")
		}
		if err := fs.WaitUntilReady(ctx, daemon.SharedNydusDaemonID); err != nil {
			return nil, errors.Wrap(err, "failed to wait shared daemon")
		}
	}

	return &fs, nil
}

func (fs *filesystem) newSharedDaemon() (*daemon.Daemon, error) {
	d, err := daemon.NewDaemon(
		daemon.WithID(daemon.SharedNydusDaemonID),
		daemon.WithSnapshotID(daemon.SharedNydusDaemonID),
		daemon.WithSocketDir(fs.SocketRoot()),
		daemon.WithSnapshotDir(fs.SnapshotRoot()),
		daemon.WithLogDir(fs.LogRoot()),
		daemon.WithRootMountPoint(filepath.Join(fs.RootDir, "mnt")),
		daemon.WithSharedDaemon(),
	)
	if err != nil {
		return nil, err
	}
	if err := fs.manager.NewDaemon(d); err != nil {
		return nil, err
	}
	return d, nil
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
func (fs *filesystem) Mount(ctx context.Context, snapshotID string, labels map[string]string) (err error) {
	// If NoneDaemon mode, we don't mount nydus on host
	if !fs.hasDaemon() {
		return nil
	}

	imageID, ok := labels[label.ImageRef]
	if !ok {
		return fmt.Errorf("failed to find image ref of snapshot %s, labels %v", snapshotID, labels)
	}
	d, err := fs.newDaemon(snapshotID, imageID)
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
	err = fs.mount(d, labels)
	if err != nil {
		log.G(ctx).Errorf("failed to mount %s, %v", d.MountPoint(), err)
		return errors.Wrap(err, fmt.Sprintf("failed to mount daemon %s", d.ID))
	}
	return nil
}

// WaitUntilReady wait until daemon ready by snapshotID, it will wait until nydus domain socket established
// and the status of nydusd daemon must be ready
func (fs *filesystem) WaitUntilReady(ctx context.Context, snapshotID string) error {
	// If NoneDaemon mode, there's no need to wait for daemon ready
	if !fs.hasDaemon() {
		return nil
	}

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
	if !fs.hasDaemon() {
		return nil
	}

	id := filepath.Base(mountPoint)
	daemon, err := fs.manager.GetBySnapshotID(id)
	if err != nil {
		return err
	}
	if err := fs.manager.DestroyDaemon(daemon); err != nil {
		return errors.Wrap(err, "destroy daemon err")
	}
	if err := fs.cacheMgr.DelSnapshot(daemon.ImageID); err != nil {
		return errors.Wrap(err, "del snapshot err")
	}
	log.L.Debugf("remove snapshot %s\n", daemon.ImageID)
	fs.cacheMgr.SchedGC()
	return nil
}

func (fs *filesystem) Cleanup(ctx context.Context) error {
	if !fs.hasDaemon() {
		return nil
	}

	for _, d := range fs.manager.ListDaemons() {
		err := fs.Umount(ctx, filepath.Dir(d.MountPoint()))
		if err != nil {
			log.G(ctx).Infof("failed to umount %s err %+v", d.MountPoint(), err)
		}
	}
	return nil
}

func (fs *filesystem) MountPoint(snapshotID string) (string, error) {
	if !fs.hasDaemon() {
		// For NoneDaemon mode, just return error to use snapshotter
		// default mount point path
		return "", fmt.Errorf("don't need nydus daemon of snapshot %s", snapshotID)
	} else {
		if d, err := fs.manager.GetBySnapshotID(snapshotID); err == nil {
			if fs.mode == fspkg.SingleInstance {
				return d.SharedMountPoint(), nil
			}
			return d.MountPoint(), nil
		}
		return "", fmt.Errorf("failed to find nydus mountpoint of snapshot %s", snapshotID)
	}
}

func (fs *filesystem) BootstrapFile(id string) (string, error) {
	return daemon.GetBootstrapFile(fs.SnapshotRoot(), id)
}

func (fs *filesystem) NewDaemonConfig(labels map[string]string) (config.DaemonConfig, error) {
	imageID, ok := labels[label.ImageRef]
	if !ok {
		return config.DaemonConfig{}, fmt.Errorf("no image ID found in label")
	}

	cfg, err := config.NewDaemonConfig(fs.daemonCfg, imageID, fs.vpcRegistry, labels)
	if err != nil {
		return config.DaemonConfig{}, err
	}
	// Overriding work_dir option of nyudsd config as we want to set it
	// via snapshotter config option to let snapshotter handle blob cache GC.
	cfg.Device.Cache.Config.WorkDir = fs.cacheMgr.CacheDir()
	return cfg, nil
}

func (fs *filesystem) mount(d *daemon.Daemon, labels map[string]string) error {
	err := fs.generateDaemonConfig(d, labels)
	if err != nil {
		return err
	}
	if fs.mode == fspkg.SingleInstance {
		err = d.SharedMount()
		if err != nil {
			return errors.Wrapf(err, "failed to shared mount")
		}
		return fs.addSnapshot(d.ImageID, labels)
	}
	if err := fs.manager.StartDaemon(d); err != nil {
		return errors.Wrapf(err, "start daemon err")
	}
	return fs.addSnapshot(d.ImageID, labels)
}

func (fs *filesystem) addSnapshot(imageID string, labels map[string]string) error {
	blobs, err := fs.getBlobIDs(labels)
	if err != nil {
		return err
	}
	log.L.Infof("image %s with blob caches %v", imageID, blobs)
	return fs.cacheMgr.AddSnapshot(imageID, blobs)
}

func (fs *filesystem) newDaemon(snapshotID string, imageID string) (*daemon.Daemon, error) {
	if fs.mode == fspkg.SingleInstance {
		return fs.createSharedDaemon(snapshotID, imageID)
	}
	return fs.createNewDaemon(snapshotID, imageID)
}

// createNewDaemon create new nydus daemon by snapshotID and imageID
func (fs *filesystem) createNewDaemon(snapshotID string, imageID string) (*daemon.Daemon, error) {
	var (
		d   *daemon.Daemon
		err error
	)
	if d, err = daemon.NewDaemon(
		daemon.WithSnapshotID(snapshotID),
		daemon.WithSocketDir(fs.SocketRoot()),
		daemon.WithConfigDir(fs.ConfigRoot()),
		daemon.WithSnapshotDir(fs.SnapshotRoot()),
		daemon.WithLogDir(fs.LogRoot()),
		daemon.WithCacheDir(fs.cacheMgr.CacheDir()),
		daemon.WithImageID(imageID),
	); err != nil {
		return nil, err
	}
	if err = fs.manager.NewDaemon(d); err != nil {
		return nil, err
	}
	return d, nil
}

// createSharedDaemon create an virtual daemon from global shared daemon instance
// the global shared daemon with an special ID "shared_daemon", all virtual daemons are
// created from this daemon with api invocation
func (fs *filesystem) createSharedDaemon(snapshotID string, imageID string) (*daemon.Daemon, error) {
	var (
		sharedDaemon *daemon.Daemon
		d            *daemon.Daemon
		err          error
	)
	if sharedDaemon, err = fs.manager.GetByID(daemon.SharedNydusDaemonID); err != nil {
		return nil, err
	}
	if d, err = daemon.NewDaemon(
		daemon.WithSnapshotID(snapshotID),
		daemon.WithRootMountPoint(*sharedDaemon.RootMountPoint),
		daemon.WithSnapshotDir(fs.SnapshotRoot()),
		daemon.WithAPISock(sharedDaemon.APISock()),
		daemon.WithConfigDir(fs.ConfigRoot()),
		daemon.WithLogDir(fs.LogRoot()),
		daemon.WithCacheDir(fs.cacheMgr.CacheDir()),
		daemon.WithImageID(imageID),
	); err != nil {
		return nil, err
	}
	if err = fs.manager.NewDaemon(d); err != nil {
		return nil, err
	}
	return d, nil
}

// generateDaemonConfig generate Daemon configuration
func (fs *filesystem) generateDaemonConfig(d *daemon.Daemon, labels map[string]string) error {
	cfg, err := config.NewDaemonConfig(fs.daemonCfg, d.ImageID, fs.vpcRegistry, labels)
	if err != nil {
		return errors.Wrapf(err, "failed to generate daemon config for daemon %s", d.ID)
	}
	// Overriding work_dir option of nyudsd config as we want to set it
	// via snapshotter config option to let snapshotter handle blob cache GC.
	cfg.Device.Cache.Config.WorkDir = fs.cacheMgr.CacheDir()
	return config.SaveConfig(cfg, d.ConfigFile())
}

func (fs *filesystem) hasDaemon() bool {
	return fs.mode != fspkg.NoneInstance
}

func (fs *filesystem) getBlobIDs(labels map[string]string) ([]string, error) {
	idStr, ok := labels[utils.LayerAnnotationNydusBlobIDs]
	if !ok {
		return nil, errors.New("no blob ids found")
	}
	var result []string
	if err := json.Unmarshal([]byte(idStr), &result); err != nil {
		return nil, err
	}
	return result, nil
}
