/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/containerd/continuity/fs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/cache"
	metrics "github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/metric"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/store"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	fspkg "github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/stargz"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/label"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/signature"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/snapshot"
)

var _ snapshots.Snapshotter = &snapshotter{}

type snapshotter struct {
	context     context.Context
	root        string
	nydusdPath  string
	ms          *storage.MetaStore
	asyncRemove bool
	fs          fspkg.FileSystem
	stargzFs    fspkg.FileSystem
	manager     *process.Manager
	hasDaemon   bool
}

func (o *snapshotter) Cleanup(ctx context.Context) error {
	cleanup, err := o.cleanupDirectories(ctx)
	if err != nil {
		return err
	}

	log.G(ctx).Infof("cleanup: dirs=%v", cleanup)
	for _, dir := range cleanup {
		if err := o.cleanupSnapshotDirectory(ctx, dir); err != nil {
			log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
		}
	}
	return nil
}

func NewSnapshotter(ctx context.Context, cfg *config.Config) (snapshots.Snapshotter, error) {
	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize verifier")
	}

	cfg.DaemonMode = strings.ToLower(cfg.DaemonMode)

	db, err := store.NewDatabase(cfg.RootDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new database")
	}

	pm, err := process.NewManager(process.Opt{
		NydusdBinaryPath: cfg.NydusdBinaryPath,
		Database:         db,
		DaemonMode:       cfg.DaemonMode,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to new process manager")
	}
	cacheMgr, err := cache.NewManager(cache.Opt{
		Database: db,
		Period:   cfg.GCPeriod,
		CacheDir: cfg.CacheDir,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to new cache manager")
	}

	hasDaemon := cfg.DaemonMode != config.DaemonModeNone

	nydusFs, err := nydus.NewFileSystem(
		ctx,
		nydus.WithProcessManager(pm),
		nydus.WithCacheManager(cacheMgr),
		nydus.WithNydusdBinaryPath(cfg.NydusdBinaryPath),
		nydus.WithMeta(cfg.RootDir),
		nydus.WithDaemonConfig(cfg.DaemonCfg),
		nydus.WithVPCRegistry(cfg.ConvertVpcRegistry),
		nydus.WithVerifier(verifier),
		nydus.WithDaemonMode(cfg.DaemonMode),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize nydus filesystem")
	}

	var stargzFs fspkg.FileSystem = nil
	if cfg.EnableStargz {
		if hasDaemon {
			stargzFs, err = stargz.NewFileSystem(
				ctx,
				stargz.WithProcessManager(pm),
				stargz.WithMeta(cfg.RootDir),
				stargz.WithNydusdBinaryPath(cfg.NydusdBinaryPath),
				stargz.WithNydusImageBinaryPath(cfg.NydusImageBinaryPath),
				stargz.WithDaemonConfig(cfg.DaemonCfg),
			)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize stargz filesystem")
			}
		} else {
			// stargz support requires nydusd to run
			log.G(ctx).Info("DaemonMode is none, disable stargz support")
		}
	}

	if cfg.EnableMetrics {
		metricServer, err := metrics.NewServer(
			ctx,
			metrics.WithRootDir(cfg.RootDir),
			metrics.WithMetricsFile(cfg.MetricsFile),
			metrics.WithProcessManager(pm),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to new metric server")
		}
		// Start metrics http server.
		go func() {
			if err := metricServer.Serve(ctx); err != nil {
				log.G(ctx).Error(err)
			}
		}()
	}

	if err := os.MkdirAll(cfg.RootDir, 0700); err != nil {
		return nil, err
	}

	supportsDType, err := getSupportsDType(cfg.RootDir)
	if err != nil {
		return nil, err
	}
	if !supportsDType {
		return nil, fmt.Errorf("%s does not support d_type. If the backing filesystem is xfs, please reformat with ftype=1 to enable d_type support", cfg.RootDir)
	}

	ms, err := storage.NewMetaStore(filepath.Join(cfg.RootDir, "metadata.db"))
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(cfg.RootDir, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	return &snapshotter{
		context:     ctx,
		root:        cfg.RootDir,
		nydusdPath:  cfg.NydusdBinaryPath,
		ms:          ms,
		asyncRemove: cfg.AsyncRemove,
		fs:          nydusFs,
		stargzFs:    stargzFs,
		hasDaemon:   hasDaemon,
	}, nil
}

func (o *snapshotter) Stat(ctx context.Context, key string) (snapshots.Info, error) {
	_, info, _, err := snapshot.GetSnapshotInfo(ctx, o.ms, key)
	return info, err
}

func (o *snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	return snapshot.UpdateSnapshotInfo(ctx, o.ms, info, fieldpaths...)
}

func (o *snapshotter) Usage(ctx context.Context, key string) (snapshots.Usage, error) {
	id, info, usage, err := snapshot.GetSnapshotInfo(ctx, o.ms, key)
	if err != nil {
		return snapshots.Usage{}, err
	}
	upperPath := o.upperPath(id)
	if info.Kind == snapshots.KindActive {
		du, err := fs.DiskUsage(ctx, upperPath)
		if err != nil {
			return snapshots.Usage{}, err
		}
		usage = snapshots.Usage(du)
	}
	return usage, nil
}

func (o *snapshotter) getSnapShot(ctx context.Context, key string) (*storage.Snapshot, error) {
	return snapshot.GetSnapshot(ctx, o.ms, key)
}

func (o *snapshotter) Mounts(ctx context.Context, key string) ([]mount.Mount, error) {
	s, err := o.getSnapShot(ctx, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get active mount")
	}
	if id, info, rErr := o.findNydusMetaLayer(ctx, key); rErr == nil {
		err = o.fs.WaitUntilReady(ctx, id)
		if err != nil {
			log.G(ctx).Errorf("snapshot %s is not ready, err: %v", id, err)
			return nil, err
		}
		return o.remoteMounts(ctx, *s, id, info.Labels)
	} else if o.stargzFs != nil {
		if id, _, rErr := o.findStargzMetaLayer(ctx, key); rErr == nil {
			err = o.stargzFs.WaitUntilReady(ctx, id)
			if err != nil {
				log.G(ctx).Errorf("snapshot %s is not ready, err: %v", id, err)
				return nil, err
			}
			return o.remoteMounts(ctx, *s, id, info.Labels)
		}
	}
	return o.mounts(ctx, *s)
}

func (o *snapshotter) prepareRemoteSnapshot(ctx context.Context, id string, labels map[string]string) error {
	log.G(ctx).Infof("prepare remote snapshot mountpoint %s", o.upperPath(id))
	return o.fs.Mount(o.context, id, labels)
}

func (o *snapshotter) prepareStargzRemoteSnapshot(ctx context.Context, id string, labels map[string]string) error {
	log.G(ctx).Infof("prepare stargz remote snapshot mountpoint %s", o.upperPath(id))
	return o.stargzFs.Mount(o.context, id, labels)
}

func (o *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	logCtx := log.G(ctx).WithField("key", key).WithField("parent", parent)

	s, err := o.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
	if err != nil {
		return nil, err
	}

	var base snapshots.Info
	for _, opt := range opts {
		if err := opt(&base); err != nil {
			return nil, err
		}
	}

	logCtx.Infof("prepare key %s parent %s labels", key, parent)
	if target, ok := base.Labels[label.TargetSnapshotLabel]; ok {
		// check if image layer is nydus layer
		if o.fs.Support(ctx, base.Labels) {
			logCtx.Infof("nydus data layer, skip download and unpack %s", key)
			err := o.Commit(ctx, target, key, append(opts, snapshots.WithLabels(base.Labels))...)
			if err == nil || errdefs.IsAlreadyExists(err) {
				return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "target snapshot %q", target)
			}
		}
		// check if image layer is stargz layer, we need to download the stargz toc and convert it to nydus formated meta
		// then skip layer download
		if o.stargzFs != nil && o.stargzFs.Support(ctx, base.Labels) {
			// Mark this snapshot as remote
			base.Labels[label.RemoteLabel] = fmt.Sprintf("remote snapshot")
			err := o.stargzFs.PrepareLayer(ctx, s, base.Labels)
			if err != nil {
				logCtx.Errorf("failed to prepare stargz layer of snapshot ID %s, err: %v", s.ID, err)
			} else {
				err := o.Commit(ctx, target, key, append(opts, snapshots.WithLabels(base.Labels))...)
				if err == nil || errdefs.IsAlreadyExists(err) {
					return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "target snapshot %q", target)
				}
			}
		}
	}
	if prepareForContainer(base) {
		logCtx.Infof("prepare for container layer %s", key)
		if id, info, err := o.findNydusMetaLayer(ctx, key); err == nil {
			logCtx.Infof("found nydus meta layer id %s, parpare remote snapshot", id)
			if err := o.prepareRemoteSnapshot(ctx, id, info.Labels); err != nil {
				return nil, err
			}
			return o.remoteMounts(ctx, s, id, info.Labels)
		} else if o.stargzFs != nil {
			if id, info, err := o.findStargzMetaLayer(ctx, key); err == nil {
				logCtx.Infof("found stargz meta layer id %s, parpare remote snapshot", id)
				if err := o.prepareStargzRemoteSnapshot(ctx, id, info.Labels); err != nil {
					return nil, err
				}
				return o.remoteMounts(ctx, s, id, info.Labels)
			}
		}
	}
	return o.mounts(ctx, s)
}

func (o *snapshotter) findStargzMetaLayer(ctx context.Context, key string) (string, snapshots.Info, error) {
	return snapshot.FindSnapshot(ctx, o.ms, key, func(info snapshots.Info) bool {
		_, ok := info.Labels[label.RemoteLabel]
		return ok
	})
}

func (o *snapshotter) findNydusMetaLayer(ctx context.Context, key string) (string, snapshots.Info, error) {
	return snapshot.FindSnapshot(ctx, o.ms, key, func(info snapshots.Info) bool {
		_, ok := info.Labels[label.NydusMetaLayer]
		return ok
	})
}

func prepareForContainer(info snapshots.Info) bool {
	_, ok := info.Labels[label.CRIImageLayer]
	return !ok
}

func (o *snapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	s, err := o.createSnapshot(ctx, snapshots.KindView, key, parent, opts)
	if err != nil {
		return nil, err
	}
	return o.mounts(ctx, s)
}

func (o *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
		}
	}()

	// grab the existing id
	id, _, _, err := storage.GetInfo(ctx, key)
	if err != nil {
		return err
	}

	usage, err := fs.DiskUsage(ctx, o.upperPath(id))
	if err != nil {
		return err
	}

	if _, err = storage.CommitActive(ctx, key, name, snapshots.Usage(usage), opts...); err != nil {
		return errors.Wrap(err, "failed to commit snapshot")
	}

	return t.Commit()
}

func (o *snapshotter) Remove(ctx context.Context, key string) error {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
		}
	}()

	_, _, err = storage.Remove(ctx, key)
	if err != nil {
		return errors.Wrap(err, "failed to remove")
	}

	if !o.asyncRemove {
		var removals []string
		removals, err = o.getCleanupDirectories(ctx)
		if err != nil {
			return errors.Wrap(err, "unable to get directories for removal")
		}

		// Remove directories after the transaction is closed, failures must not
		// return error since the transaction is committed with the removal
		// key no longer available.
		defer func() {
			if err == nil {
				for _, dir := range removals {
					if err := o.cleanupSnapshotDirectory(ctx, dir); err != nil {
						log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
					}
				}
			}
		}()

	}

	return t.Commit()
}

func (o *snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	if err != nil {
		return err
	}
	defer t.Rollback()
	return storage.WalkInfo(ctx, fn, fs...)
}

func (o *snapshotter) Close() error {
	err := o.fs.Cleanup(context.Background())
	if err != nil {
		log.L.Errorf("failed to clean up remote snapshot, err %v", err)
	}
	return o.ms.Close()
}

func (o *snapshotter) upperPath(id string) string {
	if mnt, err := o.fs.MountPoint(id); err == nil {
		return mnt
	}

	if o.stargzFs != nil {
		if mnt, err := o.stargzFs.MountPoint(id); err == nil {
			return mnt
		}
	}

	return filepath.Join(o.root, "snapshots", id, "fs")
}

func (o *snapshotter) workPath(id string) string {
	return filepath.Join(o.root, "snapshots", id, "work")
}

func (o *snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ storage.Snapshot, err error) {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return storage.Snapshot{}, err
	}

	var td, path string
	defer func() {
		if err != nil {
			if td != "" {
				if err1 := o.cleanupSnapshotDirectory(ctx, td); err1 != nil {
					log.G(ctx).WithError(err1).Warn("failed to cleanup temp snapshot directory")
				}
			}
			if path != "" {
				if err1 := o.cleanupSnapshotDirectory(ctx, path); err1 != nil {
					log.G(ctx).WithError(err1).WithField("path", path).Error("failed to reclaim snapshot directory, directory may need removal")
					err = errors.Wrapf(err, "failed to remove path: %v", err1)
				}
			}
		}
	}()

	td, err = o.prepareDirectory(ctx, o.snapshotRoot(), kind)
	if err != nil {
		if rerr := t.Rollback(); rerr != nil {
			log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
		}
		return storage.Snapshot{}, errors.Wrap(err, "failed to create prepare snapshot dir")
	}
	rollback := true
	defer func() {
		if rollback {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
		}
	}()

	s, err := storage.CreateSnapshot(ctx, kind, key, parent, opts...)
	if err != nil {
		return storage.Snapshot{}, errors.Wrap(err, "failed to create snapshot")
	}

	if len(s.ParentIDs) > 0 {
		st, err := os.Stat(o.upperPath(s.ParentIDs[0]))
		if err != nil {
			return storage.Snapshot{}, errors.Wrap(err, "failed to stat parent")
		}

		stat := st.Sys().(*syscall.Stat_t)

		if err := os.Lchown(filepath.Join(td, "fs"), int(stat.Uid), int(stat.Gid)); err != nil {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
			return storage.Snapshot{}, errors.Wrap(err, "failed to chown")
		}
	}

	path = o.snapshotDir(s.ID)
	if err = os.Rename(td, path); err != nil {
		return storage.Snapshot{}, errors.Wrap(err, "failed to rename")
	}
	td = ""

	rollback = false
	if err = t.Commit(); err != nil {
		return storage.Snapshot{}, errors.Wrap(err, "commit failed")
	}

	return s, nil
}

func bindMount(source string) []mount.Mount {
	return []mount.Mount{
		{
			Type:   "bind",
			Source: source,
			Options: []string{
				"ro",
				"rbind",
			},
		},
	}
}

func overlayMount(options []string) []mount.Mount {
	return []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}
}

func (o *snapshotter) remoteMounts(ctx context.Context, s storage.Snapshot, id string, labels map[string]string) ([]mount.Mount, error) {
	var options []string
	if o.hasDaemon {
		if s.Kind == snapshots.KindActive {
			options = append(options,
				fmt.Sprintf("workdir=%s", o.workPath(s.ID)),
				fmt.Sprintf("upperdir=%s", o.upperPath(s.ID)),
			)
		} else if len(s.ParentIDs) == 1 {
			return bindMount(o.upperPath(s.ParentIDs[0])), nil
		}
		lowerDirOption := fmt.Sprintf("lowerdir=%s", o.upperPath(id))
		options = append(options, lowerDirOption)
		log.G(ctx).Infof("mount options %v", options)
		return overlayMount(options), nil
	} else {
		// Only nydus can work without daemon
		source, err := o.fs.BootstrapFile(id)
		if err != nil {
			return nil, err
		}

		cfg, err := o.fs.NewDaemonConfig(labels)
		if err != nil {
			return nil, errors.Wrapf(err, fmt.Sprintf("remoteMounts: failed to generate nydus config for snapshot %s, label: %v", id, labels))
		}

		b, err := json.Marshal(cfg)
		if err != nil {
			return nil, errors.Wrapf(err, "remoteMounts: failed to marshal config")
		}

		configContent := string(b)
		configOption := fmt.Sprintf("config=%s", configContent)
		options = append(options, configOption)

		// We already Marshal config and save it in configContent, reset Auth and
		// RegistryToken so it could be printed and to make debug easier
		cfg.Device.Backend.Config.Auth = ""
		cfg.Device.Backend.Config.RegistryToken = ""
		b, err = json.Marshal(cfg)
		if err != nil {
			return nil, errors.Wrapf(err, "remoteMounts: failed to marshal config")
		}
		log.G(ctx).Infof("Bootstrap file for snapshotID %s: %s, config %s", id, source, string(b))

		return []mount.Mount{
			{
				Type:    "nydus",
				Source:  source,
				Options: options,
			},
		}, nil
	}
}

func (o *snapshotter) mounts(ctx context.Context, s storage.Snapshot) ([]mount.Mount, error) {
	if len(s.ParentIDs) == 0 {
		// if we only have one layer/no parents then just return a bind mount as overlay
		// will not work
		roFlag := "rw"
		if s.Kind == snapshots.KindView {
			roFlag = "ro"
		}

		return []mount.Mount{
			{
				Source: o.upperPath(s.ID),
				Type:   "bind",
				Options: []string{
					roFlag,
					"rbind",
				},
			},
		}, nil
	}
	var options []string

	if s.Kind == snapshots.KindActive {
		options = append(options,
			fmt.Sprintf("workdir=%s", o.workPath(s.ID)),
			fmt.Sprintf("upperdir=%s", o.upperPath(s.ID)),
		)
	} else if len(s.ParentIDs) == 1 {
		return []mount.Mount{
			{
				Source: o.upperPath(s.ParentIDs[0]),
				Type:   "bind",
				Options: []string{
					"ro",
					"rbind",
				},
			},
		}, nil
	}

	parentPaths := make([]string, len(s.ParentIDs))
	for i := range s.ParentIDs {
		parentPaths[i] = o.upperPath(s.ParentIDs[i])
	}

	options = append(options, fmt.Sprintf("lowerdir=%s", strings.Join(parentPaths, ":")))
	log.G(ctx).Infof("mount options %s", options)
	return []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}, nil
}

func (o *snapshotter) prepareDirectory(ctx context.Context, snapshotDir string, kind snapshots.Kind) (string, error) {
	td, err := ioutil.TempDir(snapshotDir, "new-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp dir")
	}

	if err := os.Mkdir(filepath.Join(td, "fs"), 0755); err != nil {
		return td, err
	}

	if kind == snapshots.KindActive {
		if err := os.Mkdir(filepath.Join(td, "work"), 0711); err != nil {
			return td, err
		}
	}

	return td, nil
}

func (o *snapshotter) getCleanupDirectories(ctx context.Context) ([]string, error) {
	ids, err := storage.IDMap(ctx)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(o.snapshotRoot())
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	dirs, err := fd.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	var cleanup []string
	for _, d := range dirs {
		if _, ok := ids[d]; ok {
			continue
		}
		// When it quits, there will be nothing inside
		cleanup = append(cleanup, o.snapshotDir(d))
	}

	return cleanup, nil
}

func (o *snapshotter) cleanupDirectories(ctx context.Context) ([]string, error) {
	// Get a write transaction to ensure no other write transaction can be entered
	// while the cleanup is scanning.
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return nil, err
	}
	defer t.Rollback()
	return o.getCleanupDirectories(ctx)
}

func (o *snapshotter) cleanupSnapshotDirectory(ctx context.Context, dir string) error {
	// On a remote snapshot, the layer is mounted on the "fs" directory.
	// We use Filesystem's Unmount API so that it can do necessary finalization
	// before/after the unmount.
	log.G(ctx).WithField("dir", dir).Infof("cleanupSnapshotDirectory %s", dir)
	if err := o.fs.Umount(ctx, dir); err != nil && !os.IsNotExist(err) {
		log.G(ctx).WithError(err).WithField("dir", dir).Error("failed to unmount")
	} else if o.stargzFs != nil {
		if err := o.stargzFs.Umount(ctx, dir); err != nil && !os.IsNotExist(err) {
			log.G(ctx).WithError(err).WithField("dir", dir).Error("failed to unmount")
		}
	}

	if err := os.RemoveAll(dir); err != nil {
		return errors.Wrapf(err, "failed to remove directory %q", dir)
	}
	return nil
}

func (o *snapshotter) snapshotRoot() string {
	return filepath.Join(o.root, "snapshots")
}

func (o *snapshotter) snapshotDir(id string) string {
	return filepath.Join(o.snapshotRoot(), id)
}

func (o *snapshotter) socketRoot() string {
	return filepath.Join(o.root, "socket")
}

func (o *snapshotter) configRoot() string {
	return filepath.Join(o.root, "config")
}

func (o *snapshotter) logRoot() string {
	return filepath.Join(o.root, "logs")
}
