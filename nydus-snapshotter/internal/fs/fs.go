/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/fs_mock.go -source fs.go -package mocks

// Package fs runs one nydus daemon per image and mounts it, the remote file
// system behind the snapshotter, as stargz-snapshotter's FileSystem, refer to
// https://github.com/containerd/stargz-snapshotter/blob/main/snapshot/snapshot.go.
package fs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

// mountTimeoutFactor bounds a whole Mount, the wait for another start or
// teardown of the image included, to that many mount timeouts.
const mountTimeoutFactor = 2

// Image identifies the nydus image a container rootfs is built on.
type Image struct {
	// ChainID is the chain ID of the bootstrap layer, its snapshot.ref.
	ChainID string

	// Ref is the image reference blobs are read from.
	Ref string

	// BootstrapDir is the bootstrap snapshot's fs dir holding image/.
	BootstrapDir string

	// PrefetchScope overrides the configured prefetch scope when set.
	PrefetchScope string
}

// UsedFunc returns the chain IDs of the images snapshots still use.
type UsedFunc func(ctx context.Context) (map[string]struct{}, error)

// FileSystem serves the images of one nydus format version.
type FileSystem interface {
	// Mount ensures the daemon serving the image is ready and returns its
	// mountpoint.
	Mount(ctx context.Context, image *Image) (string, error)

	// Release stops every daemon whose image is no longer used and forgets
	// daemons that are gone.
	Release(ctx context.Context, used UsedFunc) error

	// RunningBlobs returns the IDs of the blobs running daemons reference.
	RunningBlobs(ctx context.Context) (map[string]struct{}, error)

	// Reload applies a reloaded config: cgroup limits now, the dragonfly
	// section to daemons started later.
	Reload(ctx context.Context, cfg *config.Config) error
}

// fileSystem is the Nydus v3 FileSystem: one systemd unit per image, keyed
// by the bootstrap layer's chain ID.
type fileSystem struct {
	// cfg is the current config, swapped on reload.
	cfg atomic.Pointer[config.Config]

	// systemd starts and stops daemon units.
	systemd systemd.Manager

	// store persists instances and blob access times.
	store store.Store

	// keychain resolves registry credentials.
	keychain auth.Keychain

	// hosts resolves registry endpoints from certs.d.
	hosts *registry.Hosts

	// driver mounts images.
	driver Driver

	// newClient returns a client of a daemon API socket.
	newClient func(socket string) nydusd.Client

	// locker serializes the start and teardown of one image.
	locker kmutex.KeyedLocker

	// startLock is held from linking a daemon's blob metas into the cache
	// until its record protects them, so cache GC never evicts a blob the
	// daemon is about to use.
	startLock sync.Locker

	// exited holds the daemons found exited while in use, counted once.
	exited sync.Map

	// slicesMu serializes startSlices, so the limits of the latest config
	// are the ones applied last.
	slicesMu sync.Mutex

	// limitsDeferred reports a slice memory.max deferred until usage drops.
	limitsDeferred atomic.Bool
}

// New Nydus v3 file system. It starts the daemon slices with their limits.
func New(ctx context.Context, cfg *config.Config, manager systemd.Manager, s store.Store, keychain auth.Keychain, startLock sync.Locker) (FileSystem, error) {
	driver, err := newDriver(cfg.Nydusd.Driver)
	if err != nil {
		return nil, err
	}

	for _, dir := range []string{cfg.CacheDir(), cfg.InstancesDir(), cfg.RuntimesDir(), cfg.Nydusd.LogDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	f := &fileSystem{
		systemd:   manager,
		store:     s,
		keychain:  keychain,
		hosts:     registry.NewHosts(cfg.Registry.ConfigPath),
		driver:    driver,
		newClient: nydusd.NewClient,
		locker:    kmutex.New(),
		startLock: startLock,
	}
	f.cfg.Store(cfg)

	if err := f.startSlices(ctx); err != nil {
		return nil, err
	}

	return f, nil
}

// Mount ensures the daemon serving the image is ready and returns its
// mountpoint.
func (f *fileSystem) Mount(ctx context.Context, image *Image) (string, error) {
	id, err := parseDaemonID(image.ChainID)
	if err != nil {
		return "", err
	}

	// Bound the whole mount, as stargz-snapshotter bounds its Mount:
	// containerd holds its metadata lock across Prepare and View.
	ctx, cancel := context.WithTimeout(ctx, mountTimeoutFactor*time.Duration(f.cfg.Load().Nydusd.MountTimeout))
	defer cancel()
	if err := f.locker.Lock(ctx, string(id)); err != nil {
		return "", fmt.Errorf("lock daemon %s: %w", id.Unit(), err)
	}
	defer f.locker.Unlock(string(id))

	cfg := f.cfg.Load()
	d := f.daemon(cfg, id)
	state, err := f.settledState(ctx, cfg, d.Instance.Unit)
	if err != nil {
		return "", err
	}

	// Reuse a running daemon. One that does not answer may still serve
	// containers, so it is reported unavailable and never stopped here;
	// teardown stops it once unused.
	if state == systemd.ActiveStateActive {
		if err := f.ready(ctx, d); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}

			// Only the class reaches containerd: a hung API's timeout would
			// otherwise resolve to DeadlineExceeded.
			return "", fmt.Errorf("daemon %s is not ready: %v: %w", d.Instance.Unit, err, errdefs.ErrUnavailable) //nolint:errorlint
		}

		if err := f.recordRunning(d.Instance, image); err != nil {
			return "", err
		}

		return d.Instance.Mountpoint, nil
	}

	start := time.Now()
	if err := f.start(ctx, cfg, d, image); err != nil {
		metrics.DaemonStartFailureTotal.Inc()

		// Never leave a half started daemon or its record behind.
		if stopErr := f.stop(context.WithoutCancel(ctx), d); stopErr != nil {
			log.G(ctx).WithError(stopErr).WithField("unit", d.Instance.Unit).Error("stop daemon after failed start")
		}

		return "", err
	}
	metrics.DaemonStartDuration.Observe(time.Since(start).Seconds())
	f.exited.Delete(id)

	// A reload that listed the units before this one started missed it.
	if latest := f.cfg.Load(); latest != cfg {
		if err := f.systemd.SetResources(ctx, d.Instance.Unit, f.daemonResources(latest)); err != nil {
			log.G(ctx).WithError(err).WithField("unit", d.Instance.Unit).Warn("apply reloaded daemon limits")
		}
	}

	return d.Instance.Mountpoint, nil
}

// Release stops every daemon whose image is no longer used and forgets
// daemons that are gone.
func (f *fileSystem) Release(ctx context.Context, used UsedFunc) error {
	// Retry a deferred memory.max now that usage may have dropped.
	if f.limitsDeferred.Load() {
		if err := f.startSlices(ctx); err != nil {
			log.G(ctx).WithError(err).Warn("apply deferred slice limits")
		}
	}

	cfg := f.cfg.Load()
	units, err := f.systemd.ListUnits(ctx, cfg.Cgroup.Slice, unitPattern)
	if err != nil {
		return err
	}

	instances, err := f.store.ListInstances()
	if err != nil {
		return err
	}

	// Mark the images in use with one walk; only the other daemons are
	// checked again under their lock, as containerd's GC marks once before it
	// sweeps.
	inUse, err := used(ctx)
	if err != nil {
		return err
	}

	// Units are the source of truth; records cover daemons that already exited.
	ids := make(map[daemonID]struct{}, len(units)+len(instances))
	running := 0
	for name, state := range units {
		if id, ok := daemonIDOfUnit(name); ok {
			ids[id] = struct{}{}
			if state != systemd.ActiveStateInactive && state != systemd.ActiveStateFailed {
				running++
			}
		}
	}
	metrics.DaemonRunning.Set(float64(running))

	for _, instance := range instances {
		if id, err := parseDaemonID(instance.ChainID); err == nil {
			ids[id] = struct{}{}
		}
	}

	var errs []error
	for id := range ids {
		if _, ok := inUse[id.ChainID()]; ok && f.isRunning(units[id.Unit()]) {
			continue
		}

		if err := f.release(ctx, cfg, id, used); err != nil {
			errs = append(errs, fmt.Errorf("release %s: %w", id.Unit(), err))
		}
	}

	return errors.Join(errs...)
}

// release stops the daemon of an image when the image is unused.
func (f *fileSystem) release(ctx context.Context, cfg *config.Config, id daemonID, used UsedFunc) error {
	if err := f.locker.Lock(ctx, string(id)); err != nil {
		return err
	}
	defer f.locker.Unlock(string(id))

	// Count users under the lock, so a container prepared meanwhile keeps
	// its daemon.
	images, err := used(ctx)
	if err != nil {
		return err
	}
	_, inUse := images[id.ChainID()]

	d := f.daemon(cfg, id)
	state, err := f.systemd.ActiveState(ctx, d.Instance.Unit)
	if err != nil {
		return err
	}

	running := f.isRunning(state)
	switch {
	case inUse && running:
		return nil
	case inUse:
		// Keep the record, so the daemon's files are cleaned up once unused.
		// A daemon whose tmpfs runtime dir is gone went with a reboot, which
		// is no crash.
		if _, err := os.Stat(filepath.Dir(d.Config)); err != nil {
			return nil
		}

		if _, counted := f.exited.LoadOrStore(id, struct{}{}); !counted {
			metrics.DaemonUnexpectedExitTotal.Inc()
			log.G(ctx).WithField("unit", d.Instance.Unit).Warn("daemon exited while in use, its containers must be recreated")
		}

		return nil
	default:
		log.G(ctx).WithField("unit", d.Instance.Unit).Info("stopping unused daemon")
		f.exited.Delete(id)
		if err := f.stop(ctx, d); err != nil {
			return err
		}

		if err := os.RemoveAll(d.LogDir); err != nil {
			return fmt.Errorf("remove %s: %w", d.LogDir, err)
		}

		return nil
	}
}

// isRunning reports whether a unit state is a daemon that runs or starts.
func (f *fileSystem) isRunning(state string) bool {
	return state == systemd.ActiveStateActive || state == systemd.ActiveStateActivating
}

// RunningBlobs returns the IDs of the blobs running daemons reference.
func (f *fileSystem) RunningBlobs(ctx context.Context) (map[string]struct{}, error) {
	// A start records its instance before its unit and teardown deletes the
	// record after the unit, so the records hold every running daemon without
	// asking systemd, as containerd's GC marks from its own database alone.
	instances, err := f.store.ListInstances()
	if err != nil {
		return nil, err
	}

	blobs := map[string]struct{}{}
	for _, instance := range instances {
		for _, blob := range instance.Blobs {
			blobs[blob] = struct{}{}
		}
	}

	return blobs, nil
}

// Reload applies a reloaded config: cgroup limits now, the dragonfly section
// to daemons started later.
func (f *fileSystem) Reload(ctx context.Context, cfg *config.Config) error {
	f.cfg.Store(cfg)
	if err := f.startSlices(ctx); err != nil {
		// Teardown passes retry deferred limits.
		f.limitsDeferred.Store(true)
		return err
	}

	units, err := f.systemd.ListUnits(ctx, cfg.Cgroup.Slice, unitPattern)
	if err != nil {
		return err
	}

	var errs []error
	for name := range units {
		errs = append(errs, f.systemd.SetResources(ctx, name, f.daemonResources(cfg)))
	}

	return errors.Join(errs...)
}
