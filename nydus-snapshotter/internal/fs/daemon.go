/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// pollInterval is the interval of unit state polling.
	pollInterval = 100 * time.Millisecond

	// oomScoreAdjust keeps daemons away from the OOM killer, as
	// containerd.service does.
	oomScoreAdjust = -999

	// limitNOFILE is the open file limit of a daemon, the same as the
	// snapshotter's own unit. nydus holds a file per blob and per FUSE handle
	// and, unlike a Go program, does not raise its own soft limit.
	limitNOFILE = 1048576
)

// Daemon is what a driver needs to know about the daemon it mounts for.
type Daemon struct {
	// Instance is the daemon's record.
	Instance *store.Instance

	// InstanceDir is the daemon's persistent directory, holding its bootstrap
	// and its mountpoint.
	InstanceDir string

	// RuntimeDir is the daemon's tmpfs directory, holding its config.
	RuntimeDir string

	// ConfigPath is the daemon's rendered config file.
	ConfigPath string

	// LogDir is the daemon's log directory.
	LogDir string

	// LogLevel is the daemon's log level.
	LogLevel string

	// LogMaxFiles is the number of log files the daemon keeps.
	LogMaxFiles int

	// id identifies the daemon.
	id daemonID
}

// daemon returns the paths of the daemon serving an image.
func (f *fileSystem) daemon(cfg *config.Config, id daemonID) *Daemon {
	instanceDir, runtimeDir := cfg.InstanceDir(string(id)), cfg.RuntimeDir(string(id))
	return &Daemon{
		Instance: &store.Instance{
			ChainID:    id.ChainID(),
			Driver:     f.driver.Name(),
			Bootstrap:  filepath.Join(instanceDir, bootstrapFile),
			Mountpoint: filepath.Join(instanceDir, "mnt"),
			APISocket:  cfg.APISocket(string(id)),
			Unit:       id.Unit(),
		},
		InstanceDir: instanceDir,
		RuntimeDir:  runtimeDir,
		ConfigPath:  filepath.Join(runtimeDir, "config.yaml"),
		LogDir:      filepath.Join(cfg.Nydusd.LogDir, string(id)),
		LogLevel:    cfg.Nydusd.LogLevel,
		LogMaxFiles: cfg.Nydusd.LogMaxFiles,
		id:          id,
	}
}

// reuse returns the mountpoint of a running daemon once it answers. One that
// does not answer may still serve containers, so it is reported unavailable
// and never stopped here; Release stops it once unused.
func (f *fileSystem) reuse(ctx context.Context, d *Daemon, image *Image) (string, error) {
	if err := f.ready(ctx, d); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("check daemon %s: %w", d.Instance.Unit, ctxErr)
		}

		// Only the class reaches containerd: a hung API's timeout would
		// otherwise resolve to DeadlineExceeded.
		return "", fmt.Errorf("daemon %s is not ready: %v: %w", d.Instance.Unit, err, errdefs.ErrUnavailable) //nolint:errorlint // the cause is named, only the class is wrapped
	}

	if err := f.recordRunning(ctx, d.Instance, image); err != nil {
		return "", err
	}

	return d.Instance.Mountpoint, nil
}

// start prepares the daemon's files, renders its config and starts its
// unit, whose start job ends once the daemon reports ready.
func (f *fileSystem) start(ctx context.Context, cfg *config.Config, d *Daemon, ref *registry.Reference, image *Image) error {
	// Hold off cache GC until the record protects the blobs; a running
	// daemon's blobs are protected by its record alone.
	f.startLock.Lock()
	err := f.prepare(cfg, d, ref, image)
	f.startLock.Unlock()
	if err != nil {
		return err
	}

	if err := f.renderConfig(ctx, cfg, d, ref, image.PrefetchScope); err != nil {
		return err
	}

	unit, err := f.daemonUnit(cfg, d, ref)
	if err != nil {
		return err
	}

	// The unit is Type=notify: its start job ends once the daemon sent
	// READY=1, or fails when the daemon exits or the start timeout passes.
	if err := f.systemd.StartTransientUnit(ctx, unit); err != nil {
		return fmt.Errorf("%w, see journalctl -u %s and %s", err, d.Instance.Unit, d.LogDir)
	}

	// Check once what ready stands for, so a daemon that reported it without
	// its mount or its API fails here and not under a container.
	if err := f.ready(ctx, d); err != nil {
		return fmt.Errorf("daemon %s reported ready but is not: %w", d.Instance.Unit, err)
	}

	if err := f.identify(ctx, d.Instance); err != nil {
		return err
	}

	if err := f.store.PutInstance(d.Instance); err != nil {
		return fmt.Errorf("record instance: %w", err)
	}

	if err := f.store.TouchBlobs(d.Instance.Blobs, time.Now()); err != nil {
		log.G(ctx).WithError(err).Warn("record blob access time")
	}

	return nil
}

// prepare cleans up what a dead daemon left behind, links the bootstrap,
// seeds the cache and records the instance.
func (f *fileSystem) prepare(cfg *config.Config, d *Daemon, ref *registry.Reference, image *Image) error {
	if err := f.driver.Unmount(d); err != nil {
		return err
	}

	if err := os.Remove(d.Instance.APISocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale api socket: %w", err)
	}

	for _, dir := range []string{d.InstanceDir, d.Instance.Mountpoint, d.RuntimeDir, d.LogDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	// Link the bootstrap so removing it from one containerd namespace cannot
	// pull it from under a daemon serving another.
	layer := NewBootstrapLayer(image.BootstrapDir)
	if err := layer.linkBootstrap(d.Instance.Bootstrap); err != nil {
		return err
	}

	if err := layer.describe(d.Instance, ref); err != nil {
		return err
	}

	if err := layer.seedCache(cfg.CacheDir(), d.Instance.Blobs); err != nil {
		return err
	}

	// Record the instance before resolving its credential, so a secret change
	// from now on reaches the daemon.
	if err := f.store.PutInstance(d.Instance); err != nil {
		return fmt.Errorf("record instance: %w", err)
	}

	return nil
}

// daemonUnit returns the transient unit running a daemon.
func (f *fileSystem) daemonUnit(cfg *config.Config, d *Daemon, ref *registry.Reference) (*systemd.Unit, error) {
	// Resolve the version current points at, so the unit names the binary it
	// runs and an upgrade switching the link meanwhile cannot change it.
	binary, err := filepath.EvalSymlinks(cfg.Nydusd.Binary)
	if err != nil {
		return nil, fmt.Errorf("resolve nydus binary: %w", err)
	}

	return &systemd.Unit{
		Name:             d.Instance.Unit,
		Description:      "nydus daemon of " + ref.Name,
		Slice:            cfg.Cgroup.Slice,
		ExecStart:        append([]string{binary}, f.driver.Args(d)...),
		Environment:      f.driver.Environment(),
		Before:           []string{"containerd.service", "kubelet.service"},
		Notify:           true,
		TimeoutStart:     time.Duration(cfg.Nydusd.MountTimeout),
		Watchdog:         time.Duration(cfg.Nydusd.WatchdogTimeout),
		TimeoutStop:      time.Duration(cfg.Nydusd.MountTimeout),
		OOMScoreAdjust:   oomScoreAdjust,
		LimitNOFILE:      limitNOFILE,
		SyslogIdentifier: "nydusd",
		LogExtraFields:   []string{"NYDUS_CHAIN_ID=" + d.Instance.ChainID},
		Resources:        f.daemonResources(cfg),
	}, nil
}

// ready returns nil when the daemon's mount is in place and its API answers.
func (f *fileSystem) ready(ctx context.Context, d *Daemon) error {
	mounted, err := f.driver.Mounted(d)
	if err != nil {
		return err
	}

	if !mounted {
		return fmt.Errorf("%s is not mounted", d.Instance.Mountpoint)
	}

	return f.newClient(d.Instance.APISocket).Ready(ctx)
}

// settledState returns the unit's active state once it is neither activating
// nor deactivating.
func (f *fileSystem) settledState(ctx context.Context, cfg *config.Config, unit string) (systemd.ActiveState, error) {
	var state systemd.ActiveState
	err := wait.PollUntilContextTimeout(ctx, pollInterval, time.Duration(cfg.Nydusd.MountTimeout), true, func(ctx context.Context) (bool, error) {
		var err error
		state, err = f.systemd.ActiveState(ctx, unit)
		return state != systemd.ActiveStateActivating && state != systemd.ActiveStateDeactivating, err
	})

	return state, err
}

// identify asks a daemon for its version and capabilities and fills them
// into its record, as kubelet asks a CRI runtime for its version when it
// connects, refer to
// https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto.
// Optional calls are gated on the capabilities where they are made; only a
// daemon that does not serve this API version is refused.
func (f *fileSystem) identify(ctx context.Context, instance *store.Instance) error {
	info, err := f.newClient(instance.APISocket).Info(ctx)
	if errdefs.IsNotImplemented(err) {
		// Only the class reaches containerd: the daemon is not one this
		// snapshotter can manage, which no retry cures.
		return fmt.Errorf("daemon %s serves no API v1, nydus and nydus-snapshotter must be of one release: %v: %w", instance.Unit, err, errdefs.ErrFailedPrecondition) //nolint:errorlint // the cause is named, only the class is wrapped
	}

	if err != nil {
		return fmt.Errorf("identify daemon %s: %w", instance.Unit, err)
	}

	instance.Version, instance.Capabilities = info.Version, info.Capabilities
	log.G(ctx).WithFields(log.Fields{"unit": instance.Unit, "version": info.Version, "git_commit": info.GitCommit, "capabilities": info.Capabilities}).Info("identified daemon")
	return nil
}

// recordRunning records a running daemon found without its record, as after
// nydusd.db was lost, or with a record that predates its version.
func (f *fileSystem) recordRunning(ctx context.Context, instance *store.Instance, image *Image) error {
	recorded, err := f.store.GetInstance(instance.ChainID)
	if err == nil && recorded.Version != "" {
		return nil
	}

	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}

	ref, err := registry.ParseReference(image.Ref)
	if err != nil {
		return err
	}

	if err := NewBootstrapLayer(image.BootstrapDir).describe(instance, ref); err != nil {
		return err
	}

	if err := f.identify(ctx, instance); err != nil {
		return err
	}

	return f.store.PutInstance(instance)
}

// abortStart cleans up after a failed start, so no half started daemon or
// record is left behind.
func (f *fileSystem) abortStart(ctx context.Context, cfg *config.Config, d *Daemon) {
	// The request may be done by now, so the stop runs on a deadline of its
	// own.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.mountBound(cfg))
	defer cancel()
	if err := f.stop(stopCtx, d); err != nil {
		log.G(ctx).WithError(err).WithField("unit", d.Instance.Unit).Error("stop daemon after failed start")
	}

	// Keep the logs failedLogRetention from this failure: a retried start
	// appends to them, which leaves their directory's time alone.
	now := time.Now()
	if err := os.Chtimes(d.LogDir, now, now); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.G(ctx).WithError(err).WithField("path", d.LogDir).Warn("touch the logs of a failed start")
	}
}

// stop stops a daemon, detaches what its mount left behind and removes its
// files and record. The daemon unmounts on SIGTERM itself. Its logs stay so
// that a failed start can be read. Release removes them with an unused
// daemon, and those of a failed start once they are failedLogRetention old.
func (f *fileSystem) stop(ctx context.Context, d *Daemon) error {
	if err := f.systemd.StopUnit(ctx, d.Instance.Unit); err != nil {
		return err
	}

	if err := f.driver.Unmount(d); err != nil {
		return err
	}

	// Record when the blobs were last used; a daemon without a record has
	// no blobs to record.
	instance, err := f.store.GetInstance(d.Instance.ChainID)
	if err != nil && !errdefs.IsNotFound(err) {
		log.G(ctx).WithError(err).Warn("read instance to record blob access time")
	}

	if instance != nil {
		if err := f.store.TouchBlobs(instance.Blobs, time.Now()); err != nil {
			log.G(ctx).WithError(err).Warn("record blob access time")
		}
	}

	for _, path := range []string{d.InstanceDir, d.RuntimeDir, d.Instance.APISocket} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}

	return f.store.DeleteInstance(d.Instance.ChainID)
}
