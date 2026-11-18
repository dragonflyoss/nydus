/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/fs_mock.go -source fs.go -package mocks

// Package fs is the remote file system behind the snapshotter: it runs one
// nydus daemon per image as a systemd unit, mounts it and keeps its registry
// credential current, as stargz-snapshotter's file system serves its
// snapshotter, refer to
// https://github.com/containerd/stargz-snapshotter/blob/main/fs/fs.go.
package fs

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/util/workqueue"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// Version is the nydus format this package serves, the value nydusify
	// gives the nydus-fs-version label of a Nydus v3 bootstrap layer.
	Version = "7"

	// mountTimeoutFactor is how many mount timeouts a Mount may take, its
	// wait for another start or release of the image included. The stop after
	// a failed start may take as many again.
	mountTimeoutFactor = 2

	// failedLogRetention keeps the logs of a daemon that failed to start,
	// which no unit or record names, long enough to be read.
	failedLogRetention = 24 * time.Hour

	// daemonConcurrency bounds the daemons released, probed or scraped at
	// once.
	daemonConcurrency = 8

	// sliceDescription describes the daemon slice in systemctl.
	sliceDescription = "nydus daemons"
)

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
	// Gatherer gathers the metrics of the running daemons.
	prometheus.Gatherer

	// Mount ensures the daemon serving the image is ready and returns its
	// mountpoint.
	Mount(ctx context.Context, image *Image) (string, error)

	// Release stops every daemon whose image is no longer used and forgets
	// daemons that are gone.
	Release(ctx context.Context, used UsedFunc) error

	// RunningBlobs returns the IDs of the blobs every recorded daemon
	// references. It fails while a daemon runs without a record, because
	// that daemon's blobs are unknown.
	RunningBlobs(ctx context.Context) (map[string]struct{}, error)

	// Reload switches to a reloaded config: its cgroup limits apply now, the
	// rest to daemons started later.
	Reload(ctx context.Context, cfg *config.Config) error

	// Run keeps the registry credentials of the daemons current until ctx is
	// done: it watches the keychain and pushes a changed credential to the
	// daemons reading with it.
	Run(ctx context.Context)
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

	// locker serializes the start and release of one image.
	locker kmutex.KeyedLocker

	// startLock is held from linking a daemon's blob metas into the cache
	// until its record protects them, so cache GC never evicts a blob the
	// daemon is about to use.
	startLock sync.Locker

	// exited holds the daemons found exited while in use, counted once.
	exited sync.Map

	// unresponsive holds the daemons that failed their last health check,
	// reported once.
	unresponsive sync.Map

	// limitsMu serializes applyLimits, so the limits of the latest config
	// are the ones applied last.
	limitsMu sync.Mutex

	// limitsDeferred reports limits Release still has to apply: a
	// slice memory.max deferred until usage drops, or limits that failed.
	limitsDeferred atomic.Bool
}

// New returns the Nydus v3 file system. It starts the daemon slice with its
// limits and applies the daemon limits to the daemons already running.
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

	deferred, err := f.startSlice(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Daemons that outlived a restart take the limits this start read.
	if err := f.limitDaemons(ctx, cfg); err != nil {
		log.G(ctx).WithError(err).Warn("apply daemon limits, retrying on release")
		deferred = true
	}
	f.limitsDeferred.Store(deferred)

	return f, nil
}

// Mount ensures the daemon serving the image is ready and returns its
// mountpoint.
func (f *fileSystem) Mount(ctx context.Context, image *Image) (string, error) {
	id, err := daemonIDFromChainID(image.ChainID)
	if err != nil {
		return "", err
	}

	// Bound the wait and the start: containerd holds its metadata lock across
	// Prepare and View.
	ctx, cancel := context.WithTimeout(ctx, f.mountBound(f.cfg.Load()))
	defer cancel()
	if err := f.locker.Lock(ctx, string(id)); err != nil {
		return "", fmt.Errorf("lock daemon %s: %w", id.Unit(), err)
	}
	defer f.locker.Unlock(string(id))

	cfg := f.cfg.Load()
	d := f.daemon(cfg, id)
	state, err := f.settledState(ctx, cfg, d.Instance.Unit)
	if err != nil {
		return "", fmt.Errorf("wait for unit %s to settle: %w", d.Instance.Unit, err)
	}

	if state == systemd.ActiveStateActive {
		return f.reuse(ctx, d, image)
	}

	// Fail fast before credentials are known, or the daemon could never get
	// them, and before anything of the daemon exists.
	if !f.keychain.Synced() {
		return "", fmt.Errorf("registry credentials are not synced yet: %w", errdefs.ErrUnavailable)
	}

	ref, err := registry.ParseReference(image.Ref)
	if err != nil {
		return "", err
	}

	start := time.Now()
	metrics.DaemonStartsTotal.Inc()
	if err := f.start(ctx, cfg, d, ref, image); err != nil {
		metrics.DaemonStartFailuresTotal.Inc()
		f.abortStart(ctx, cfg, d)
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
	// Retry deferred limits: usage may have dropped below a memory.max, and
	// what failed may work now.
	if f.limitsDeferred.Load() {
		if err := f.applyLimits(ctx); err != nil {
			log.G(ctx).WithError(err).Warn("apply deferred limits")
		}
	}

	cfg := f.cfg.Load()
	units, err := f.daemonUnits(ctx, cfg)
	if err != nil {
		return err
	}

	ids, err := f.daemonIDs(ctx, cfg, units)
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

	// A running daemon in use is kept, and probed once it is active. Any
	// other is a candidate.
	var candidates, active []daemonID
	running := 0
	for _, id := range ids {
		state := units[id]
		if state.Running() {
			running++
		}

		if _, ok := inUse[id.ChainID()]; !ok || !state.Running() {
			candidates = append(candidates, id)
		} else if state == systemd.ActiveStateActive {
			active = append(active, id)
		}
	}
	metrics.RunningDaemons.Set(float64(running))

	// Release the candidates in parallel, each under the lock of its image,
	// as kube-scheduler runs independent pieces of work, refer to
	// https://github.com/kubernetes/client-go/blob/master/util/workqueue/parallelizer.go.
	// One that fails keeps its error and does not hold up the others.
	errs := make([]error, len(candidates))
	workqueue.ParallelizeUntil(ctx, daemonConcurrency, len(candidates), func(i int) {
		if err := f.releaseDaemon(ctx, cfg, candidates[i], used); err != nil {
			errs[i] = fmt.Errorf("release %s: %w", candidates[i].Unit(), err)
		}
	})

	f.probe(ctx, cfg, active)

	// A pass that ended early says so; what it left, the next one picks up.
	return errors.Join(append(errs, ctx.Err())...)
}

// RunningBlobs returns the IDs of the blobs every recorded daemon references.
// It fails while a daemon runs without a record, because that daemon's blobs
// are unknown.
func (f *fileSystem) RunningBlobs(ctx context.Context) (map[string]struct{}, error) {
	// A start records its instance before its unit and a release deletes the
	// record after the unit, so the records hold the blobs of every daemon
	// this snapshotter started, as containerd's GC marks from its own
	// database.
	instances, err := f.store.ListInstances()
	if err != nil {
		return nil, err
	}

	recorded := make(map[string]struct{}, len(instances))
	blobs := map[string]struct{}{}
	for _, instance := range instances {
		recorded[instance.ChainID] = struct{}{}
		for _, blob := range instance.Blobs {
			blobs[blob] = struct{}{}
		}
	}

	// A daemon running without a record, as after nydusd.db was lost, reads
	// blobs no record names until its next Mount records it. Fail rather
	// than leave them out, so cache GC evicts nothing meanwhile.
	units, err := f.daemonUnits(ctx, f.cfg.Load())
	if err != nil {
		return nil, err
	}

	for id, state := range units {
		if !state.Running() {
			continue
		}

		if _, ok := recorded[id.ChainID()]; !ok {
			return nil, fmt.Errorf("daemon %s runs without a record, its blobs are unknown: %w", id.Unit(), errdefs.ErrFailedPrecondition)
		}
	}

	return blobs, nil
}

// probe checks the health of the daemons in use, counts those that do not
// answer and forgets those that are gone.
func (f *fileSystem) probe(ctx context.Context, cfg *config.Config, ids []daemonID) {
	workqueue.ParallelizeUntil(ctx, daemonConcurrency, len(ids), func(i int) {
		f.probeDaemon(ctx, f.daemon(cfg, ids[i]))
	})

	unresponsive := 0
	f.unresponsive.Range(func(id, _ any) bool {
		if slices.Contains(ids, id.(daemonID)) {
			unresponsive++
		} else {
			f.unresponsive.Delete(id)
		}

		return true
	})
	metrics.UnresponsiveDaemons.Set(float64(unresponsive))
}

// probeDaemon checks that the mount of a daemon is in place and its API
// answers. It reports the daemon when it stops and when it resumes answering,
// as kubelet's prober reports a result that changed, refer to
// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/prober/worker.go.
// A daemon that does not answer may still serve its containers, so it is
// never stopped here.
func (f *fileSystem) probeDaemon(ctx context.Context, d *Daemon) {
	err := f.ready(ctx, d)

	// A pass that ended tells nothing about the daemon.
	if ctx.Err() != nil {
		return
	}

	logger := log.G(ctx).WithField("unit", d.Instance.Unit)
	if err != nil {
		if _, reported := f.unresponsive.LoadOrStore(d.id, struct{}{}); !reported {
			logger.WithError(err).Warn("daemon does not answer, its containers may hang")
		}

		return
	}

	if _, reported := f.unresponsive.LoadAndDelete(d.id); reported {
		logger.Info("daemon answers again")
	}
}

// releaseDaemon stops the daemon of an image when the image is unused.
func (f *fileSystem) releaseDaemon(ctx context.Context, cfg *config.Config, id daemonID, used UsedFunc) error {
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

	if inUse && state.Running() {
		return nil
	}

	if inUse {
		// Keep the record, so the daemon's files are cleaned up once unused.
		// A daemon whose tmpfs runtime dir is gone went with a reboot, which
		// is no crash.
		if _, err := os.Stat(d.RuntimeDir); err != nil {
			return nil
		}

		if _, counted := f.exited.LoadOrStore(id, struct{}{}); !counted {
			metrics.DaemonUnexpectedExitsTotal.Inc()
			log.G(ctx).WithField("unit", d.Instance.Unit).Warn("daemon exited while in use, its containers must be recreated")
		}

		return nil
	}

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

// daemonIDs returns the IDs of every daemon something is left of: a unit,
// the source of truth, a record, which covers a daemon that already exited,
// or the expired logs of a failed start.
func (f *fileSystem) daemonIDs(ctx context.Context, cfg *config.Config, units map[daemonID]systemd.ActiveState) ([]daemonID, error) {
	instances, err := f.store.ListInstances()
	if err != nil {
		return nil, err
	}

	ids := slices.Collect(maps.Keys(units))
	for _, instance := range instances {
		if id, err := daemonIDFromChainID(instance.ChainID); err == nil {
			ids = append(ids, id)
		}
	}

	// Log dirs that cannot be listed hold up no release.
	expired, err := f.expiredLogDirs(cfg)
	if err != nil {
		log.G(ctx).WithError(err).Warn("list expired daemon log dirs")
	}

	ids = append(ids, expired...)
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// daemonUnits returns the active state of the daemon units of the slice by
// daemon ID. A unit of the slice that names no daemon is left out.
func (f *fileSystem) daemonUnits(ctx context.Context, cfg *config.Config) (map[daemonID]systemd.ActiveState, error) {
	units, err := f.systemd.ListUnits(ctx, cfg.Cgroup.Slice, unitPattern)
	if err != nil {
		return nil, err
	}

	daemons := make(map[daemonID]systemd.ActiveState, len(units))
	for name, state := range units {
		if id, ok := daemonIDFromUnit(name); ok {
			daemons[id] = state
		}
	}

	return daemons, nil
}

// expiredLogDirs returns the IDs of the daemons whose log dir was last
// touched over failedLogRetention ago. A failed start leaves only its logs
// behind; no unit or record names them, so Release would otherwise never
// remove them.
func (f *fileSystem) expiredLogDirs(cfg *config.Config) ([]daemonID, error) {
	entries, err := os.ReadDir(cfg.Nydusd.LogDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read log dir %s: %w", cfg.Nydusd.LogDir, err)
	}

	var ids []daemonID
	for _, entry := range entries {
		id, ok := daemonIDFromHex(entry.Name())
		if !ok {
			continue
		}

		// A log dir removed meanwhile needs no release.
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if time.Since(info.ModTime()) > failedLogRetention {
			ids = append(ids, id)
		}
	}

	return ids, nil
}

// mountBound returns how long a Mount may take.
func (f *fileSystem) mountBound(cfg *config.Config) time.Duration {
	return mountTimeoutFactor * time.Duration(cfg.Nydusd.MountTimeout)
}
