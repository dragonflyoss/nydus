/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/snapshotter_mock.go -source snapshotter.go -package mocks

// Package snapshot is the containerd snapshotter: containerd's overlay
// snapshotter for OCI layers, plus remote nydus layers served by a daemon per
// image, refer to
// https://github.com/containerd/containerd/blob/v2.2.10/plugins/snapshots/overlay/overlay.go
// and https://github.com/containerd/containerd/blob/main/docs/snapshotters/remote-snapshotter.md.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay/overlayutils"
	"github.com/containerd/continuity/fs"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	bolt "go.etcd.io/bbolt"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
)

const (
	// snapshotsDirName is the directory of snapshot directories under the
	// root, as containerd's overlay snapshotter lays them out.
	snapshotsDirName = "snapshots"

	// metadataOpenTimeout bounds waiting for another process's lock on the
	// metadata store.
	metadataOpenTimeout = 10 * time.Second
)

// Snapshotter is containerd's Snapshotter and Cleaner, plus the teardown of
// daemons whose images no snapshot uses.
type Snapshotter interface {
	snapshots.Snapshotter
	snapshots.Cleaner

	// Run tears down unused daemons on every removal and tick until ctx is
	// done.
	Run(ctx context.Context)

	// CommittedBlobs returns the IDs of the blobs committed bootstraps
	// reference.
	CommittedBlobs(ctx context.Context) (map[string]struct{}, error)
}

// snapshotter is the nydus Snapshotter.
type snapshotter struct {
	// root is the root directory of snapshots and the metadata store.
	root string

	// ms is containerd's bolt snapshot metadata store.
	ms *storage.MetaStore

	// options are the overlay mount options detected at start.
	options []string

	// fileSystems are the remote file systems keyed by nydus-fs-version.
	fileSystems map[string]nydusfs.FileSystem

	// release wakes the teardown worker, buffered by one.
	release chan struct{}
}

// New snapshotter interface. Snapshots and metadata live under root, as with
// containerd's overlay snapshotter.
func New(root string, fileSystems map[string]nydusfs.FileSystem) (Snapshotter, error) {
	if err := os.MkdirAll(filepath.Join(root, snapshotsDirName), 0o700); err != nil {
		return nil, err
	}

	supportsDType, err := fs.SupportsDType(root)
	if err != nil {
		return nil, err
	}

	if !supportsDType {
		return nil, fmt.Errorf("%s does not support d_type. If the backing filesystem is xfs, please reformat with ftype=1 to enable d_type support", root)
	}

	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"), func(options *bolt.Options) error {
		options.Timeout = metadataOpenTimeout
		return nil
	})
	if err != nil {
		return nil, err
	}

	var options []string
	userxattr, err := overlayutils.NeedsUserXAttr(root)
	if err != nil {
		log.L.WithError(err).Warnf("cannot detect whether \"userxattr\" option needs to be used, assuming to be %v", userxattr)
	}

	if userxattr {
		options = append(options, "userxattr")
	}

	if _, err := os.Stat("/sys/module/overlay/parameters/index"); err == nil {
		options = append(options, "index=off")
	}

	return &snapshotter{
		root:        root,
		ms:          ms,
		options:     options,
		fileSystems: fileSystems,
		release:     make(chan struct{}, 1),
	}, nil
}

// Stat returns the info for an active or committed snapshot by name or key.
func (s *snapshotter) Stat(ctx context.Context, key string) (info snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		_, info, _, err = storage.GetInfo(ctx, key)
		return err
	})

	return info, err
}

// Update updates the info of a snapshot.
func (s *snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (newInfo snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		newInfo, err = storage.UpdateInfo(ctx, info, fieldpaths...)
		return err
	})

	return newInfo, err
}

// Usage returns the resources taken by a snapshot: the upper directory of an
// active one, the recorded usage of a committed one.
func (s *snapshotter) Usage(ctx context.Context, key string) (snapshots.Usage, error) {
	var (
		id    string
		info  snapshots.Info
		usage snapshots.Usage
	)
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) (err error) {
		id, info, usage, err = storage.GetInfo(ctx, key)
		return err
	}); err != nil {
		return usage, err
	}

	if info.Kind == snapshots.KindActive {
		du, err := fs.DiskUsage(ctx, s.upperPath(id))
		if err != nil {
			return snapshots.Usage{}, err
		}

		usage = snapshots.Usage(du)
	}

	return usage, nil
}

// Prepare creates an active snapshot. A nydus data layer prepared by the
// unpacker is committed at once and reported as existing, so containerd never
// downloads it.
func (s *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	var base snapshots.Info
	for _, opt := range opts {
		if err := opt(&base); err != nil {
			return nil, err
		}
	}

	if target, ok := base.Labels[labelSnapshotRef]; ok && snapshotKey(key).isUnpack() && labels(base.Labels).isNydusBlob() {
		return nil, s.prepareRemoteLayer(ctx, key, parent, target, opts)
	}

	return s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

// View creates a read-only snapshot.
func (s *snapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	return s.createSnapshot(ctx, snapshots.KindView, key, parent, opts)
}

// Mounts returns the mounts of an active or view snapshot, starting the
// image's daemon again when it is gone.
func (s *snapshotter) Mounts(ctx context.Context, key string) ([]mount.Mount, error) {
	var (
		snap storage.Snapshot
		info snapshots.Info
	)
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) (err error) {
		snap, err = storage.GetSnapshot(ctx, key)
		if err != nil {
			return fmt.Errorf("get active mount: %w", err)
		}

		_, info, _, err = storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("get snapshot info: %w", err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return s.mounts(ctx, snap, info)
}

// Commit commits an active snapshot under name.
func (s *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	return s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		id, _, _, err := storage.GetInfo(ctx, key)
		if err != nil {
			return err
		}

		usage, err := fs.DiskUsage(ctx, s.upperPath(id))
		if err != nil {
			return err
		}

		if !snapshotKey(key).isUnpack() {
			opts = append(opts, s.dropRemoteLabels)
		}

		if _, err := storage.CommitActive(ctx, key, name, snapshots.Usage(usage), opts...); err != nil {
			return fmt.Errorf("commit snapshot %s: %w", key, err)
		}

		return nil
	})
}

// Remove abandons a snapshot. Its directories are removed by Cleanup and the
// daemon of its image, once unused, by the teardown worker: containerd calls
// Remove from its garbage collector under its metadata lock, so Remove does
// no slow work and never fails on teardown.
func (s *snapshotter) Remove(ctx context.Context, key string) error {
	if err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		if _, _, err := storage.Remove(ctx, key); err != nil {
			return fmt.Errorf("remove snapshot %s: %w", key, err)
		}

		return nil
	}); err != nil {
		return err
	}

	s.wakeRelease()
	return nil
}

// Walk walks the snapshots matching the filters.
func (s *snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, filters ...string) error {
	return s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return storage.WalkInfo(ctx, fn, filters...)
	})
}

// Cleanup removes the directories of removed snapshots.
func (s *snapshotter) Cleanup(ctx context.Context) error {
	var dirs []string
	// Hold a write transaction so no snapshot is created while scanning.
	if err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) (err error) {
		dirs, err = s.cleanupDirectories(ctx)
		return err
	}); err != nil {
		return err
	}

	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			log.G(ctx).WithError(err).WithField("path", dir).Warn("remove snapshot directory")
		}
	}

	s.wakeRelease()
	return nil
}

// Close closes the metadata store.
func (s *snapshotter) Close() error {
	return s.ms.Close()
}

// prepareRemoteLayer commits an empty snapshot for a nydus data layer and
// reports it as existing, so containerd adopts it and skips the download,
// refer to https://github.com/containerd/stargz-snapshotter/blob/main/snapshot/snapshot.go.
func (s *snapshotter) prepareRemoteLayer(ctx context.Context, key, parent, target string, opts []snapshots.Opt) error {
	if _, err := s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts); err != nil {
		return err
	}

	err := s.Commit(ctx, target, key, opts...)
	if err != nil {
		// Another namespace committed the same layer first; drop ours.
		if removeErr := s.Remove(ctx, key); removeErr != nil {
			log.G(ctx).WithError(removeErr).WithField("key", key).Warn("remove snapshot of a committed layer")
		}

		if !errdefs.IsAlreadyExists(err) {
			return err
		}
	}

	return fmt.Errorf("target snapshot %q: %w", target, errdefs.ErrAlreadyExists)
}

// createSnapshot creates a snapshot directory and record, then returns its
// mounts. A snapshot whose mounts fail is removed, so a retry with the same
// key does not find it.
func (s *snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ []mount.Mount, err error) {
	// Remote labels count only on unpack keys, and uid/gid mappings only on
	// other keys: containerd 1.6 copies image annotations into unpack labels.
	if snapshotKey(key).isUnpack() {
		opts = append(opts, s.dropIDMapLabels)
	} else {
		opts = append(opts, s.dropRemoteLabels)
	}

	var (
		snap     storage.Snapshot
		info     snapshots.Info
		td, path string
	)
	defer func() {
		if err == nil {
			return
		}

		if td != "" {
			if err := os.RemoveAll(td); err != nil {
				log.G(ctx).WithError(err).Warn("remove temporary snapshot directory")
			}
		}

		if path != "" {
			if removeErr := os.RemoveAll(path); removeErr != nil {
				log.G(ctx).WithError(removeErr).WithField("path", path).Error("remove snapshot directory, it may need manual removal")
				// Only err's class reaches containerd, as overlay does.
				err = fmt.Errorf("remove path: %v: %w", removeErr, err) //nolint:errorlint
			}
		}
	}()

	if err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) (err error) {
		td, err = s.prepareDirectory(kind)
		if err != nil {
			return fmt.Errorf("create snapshot directory: %w", err)
		}

		snap, err = storage.CreateSnapshot(ctx, kind, key, parent, opts...)
		if err != nil {
			return fmt.Errorf("create snapshot: %w", err)
		}

		_, info, _, err = storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("get snapshot info: %w", err)
		}

		if err := s.chownUpper(filepath.Join(td, "fs"), snap, info); err != nil {
			return err
		}

		path = filepath.Join(s.snapshotsDir(), snap.ID)
		if err := os.Rename(td, path); err != nil {
			return fmt.Errorf("rename snapshot directory: %w", err)
		}
		td = ""

		return nil
	}); err != nil {
		return nil, err
	}

	mounts, err := s.mounts(ctx, snap, info)
	if err != nil {
		path = ""
		if removeErr := s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
			_, _, err := storage.Remove(ctx, key)
			return err
		}); removeErr != nil {
			log.G(ctx).WithError(removeErr).WithField("key", key).Warn("remove snapshot whose mounts failed")
		}

		return nil, err
	}

	return mounts, nil
}

// cleanupDirectories returns the snapshot directories no snapshot owns.
func (s *snapshotter) cleanupDirectories(ctx context.Context) ([]string, error) {
	ids, err := storage.IDMap(ctx)
	if err != nil {
		return nil, err
	}

	dir := s.snapshotsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var cleanup []string
	for _, entry := range entries {
		if _, ok := ids[entry.Name()]; !ok {
			cleanup = append(cleanup, filepath.Join(dir, entry.Name()))
		}
	}

	return cleanup, nil
}

// wakeRelease wakes the teardown worker without blocking.
func (s *snapshotter) wakeRelease() {
	select {
	case s.release <- struct{}{}:
	default:
	}
}

// chownUpper gives a new snapshot's fs directory the owner its mount needs,
// as containerd's overlay snapshotter does: the root pair of the uid/gid
// mapping labels of a user namespace, otherwise the owner of the parent's
// directory, refer to
// https://github.com/containerd/containerd/blob/v2.2.10/plugins/snapshots/overlay/overlay.go.
func (s *snapshotter) chownUpper(fsDir string, snap storage.Snapshot, info snapshots.Info) error {
	uid, gid, ok, err := labels(info.Labels).rootPair()
	if err != nil {
		return err
	}

	if !ok && len(snap.ParentIDs) > 0 {
		st, err := os.Stat(s.upperPath(snap.ParentIDs[0]))
		if err != nil {
			return fmt.Errorf("stat parent: %w", err)
		}

		stat, isStat := st.Sys().(*syscall.Stat_t)
		if !isStat {
			return errors.New("stat parent: unexpected file info")
		}

		uid, gid, ok = int(stat.Uid), int(stat.Gid), true
	}

	if !ok {
		return nil
	}

	if err := os.Lchown(fsDir, uid, gid); err != nil {
		return fmt.Errorf("chown snapshot directory: %w", err)
	}

	return nil
}

// snapshotsDir returns the directory holding every snapshot directory.
func (s *snapshotter) snapshotsDir() string {
	return filepath.Join(s.root, snapshotsDirName)
}

// upperPath returns the fs directory of a snapshot.
func (s *snapshotter) upperPath(id string) string {
	return filepath.Join(s.snapshotsDir(), id, "fs")
}

// workPath returns the overlay work directory of a snapshot.
func (s *snapshotter) workPath(id string) string {
	return filepath.Join(s.snapshotsDir(), id, "work")
}

// prepareDirectory creates a temporary snapshot directory with fs and, for an
// active snapshot, work.
func (s *snapshotter) prepareDirectory(kind snapshots.Kind) (string, error) {
	td, err := os.MkdirTemp(s.snapshotsDir(), "new-")
	if err != nil {
		return "", fmt.Errorf("create temporary directory: %w", err)
	}

	if err := os.Mkdir(filepath.Join(td, "fs"), 0o755); err != nil {
		return td, err
	}

	if kind == snapshots.KindActive {
		if err := os.Mkdir(filepath.Join(td, "work"), 0o711); err != nil {
			return td, err
		}
	}

	return td, nil
}

// dropIDMapLabels removes the uid/gid mapping labels from a snapshot of an
// unpack key, which image annotations could otherwise set on containerd 1.6.
func (s *snapshotter) dropIDMapLabels(info *snapshots.Info) error {
	delete(info.Labels, snapshots.LabelSnapshotUIDMapping)
	delete(info.Labels, snapshots.LabelSnapshotGIDMapping)
	return nil
}

// dropRemoteLabels removes the nydus layer labels from a snapshot of a key
// that is no unpack key: they count only on unpack keys, so neither container
// labels nor the commit of a container snapshot can forge a nydus layer.
func (s *snapshotter) dropRemoteLabels(info *snapshots.Info) error {
	for _, label := range []string{labelNydusBlob, labelNydusBootstrap, labelNydusFSVersion, labelNydusPrefetch} {
		delete(info.Labels, label)
	}

	return nil
}
