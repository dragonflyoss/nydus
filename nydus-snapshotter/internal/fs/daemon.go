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
	"math"
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
	// pollInterval is the interval of readiness and state polling.
	pollInterval = 100 * time.Millisecond

	// oomScoreAdjust keeps daemons away from the OOM killer, as
	// containerd.service does.
	oomScoreAdjust = -999

	// limitNOFILE is the open file limit of a daemon, as the snapshotter's
	// own unit: nydus is not Go, which raises its soft limit itself, and
	// holds files per blob and per FUSE handle.
	limitNOFILE = 1048576

	// maxReadyInterval caps the readiness poll interval.
	maxReadyInterval = time.Second
)

// readyBackoff paces readiness polls from pollInterval up to
// maxReadyInterval, so daemons starting together, as after a reboot, do not
// flood systemd with calls, refer to
// https://github.com/kubernetes/apimachinery/blob/master/pkg/util/wait/backoff.go.
var readyBackoff = wait.Backoff{Duration: pollInterval, Factor: 1.5, Steps: math.MaxInt32, Cap: maxReadyInterval}

// Daemon is what a driver needs to know about the daemon it mounts for.
type Daemon struct {
	// Instance is the daemon's record.
	Instance *store.Instance

	// Config is the daemon's rendered config file.
	Config string

	// LogDir is the daemon's log directory.
	LogDir string

	// id identifies the daemon.
	id daemonID
}

// daemon returns the paths of the daemon serving an image.
func (f *fileSystem) daemon(cfg *config.Config, id daemonID) *Daemon {
	return &Daemon{
		Instance: &store.Instance{
			ChainID:    id.ChainID(),
			Driver:     f.driver.Name(),
			Bootstrap:  filepath.Join(cfg.InstanceDir(string(id)), bootstrapFile),
			Mountpoint: filepath.Join(cfg.InstanceDir(string(id)), "mnt"),
			APISocket:  cfg.APISocket(string(id)),
			Unit:       id.Unit(),
		},
		Config: filepath.Join(cfg.RuntimeDir(string(id)), "config.yaml"),
		LogDir: filepath.Join(cfg.Nydusd.LogDir, string(id)),
		id:     id,
	}
}

// start prepares the daemon's files, renders its config, starts its unit and
// waits for its mount.
func (f *fileSystem) start(ctx context.Context, cfg *config.Config, d *Daemon, image *Image) error {
	// Fail fast before credentials are known, or the daemon could never get them.
	if !f.keychain.Synced() {
		return fmt.Errorf("registry credentials are not synced yet: %w", errdefs.ErrUnavailable)
	}

	ref, err := registry.ParseReference(image.Ref)
	if err != nil {
		return err
	}

	// Hold off cache GC until the record protects the blobs; a running
	// daemon's blobs are protected by its record alone.
	f.startLock.Lock()
	err = f.prepare(cfg, d, ref, image)
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

	if err := f.systemd.StartTransientUnit(ctx, unit); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Nydusd.MountTimeout))
	defer cancel()
	if err := f.waitReady(ctx, d); err != nil {
		return fmt.Errorf("wait for daemon %s: %w", d.Instance.Unit, err)
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

	for _, dir := range []string{filepath.Dir(d.Instance.Bootstrap), d.Instance.Mountpoint, filepath.Dir(d.Config), d.LogDir} {
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

	if err := f.describe(d.Instance, ref, layer); err != nil {
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
	// Pin the version current points at, so an upgrade never swaps the binary
	// of a daemon that restarts.
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
		TimeoutStop:      time.Duration(cfg.Nydusd.MountTimeout),
		OOMScoreAdjust:   oomScoreAdjust,
		LimitNOFILE:      limitNOFILE,
		SyslogIdentifier: "nydusd",
		LogExtraFields:   []string{"NYDUS_CHAIN_ID=" + d.Instance.ChainID},
		Resources:        f.daemonResources(cfg),
	}, nil
}

// describe fills the image's reference, registry host and blobs into an
// instance record.
func (f *fileSystem) describe(instance *store.Instance, ref *registry.Reference, layer *BootstrapLayer) error {
	blobs, err := layer.Blobs()
	if err != nil {
		return err
	}

	instance.ImageRef = ref.Name
	instance.RegistryHost = ref.Host
	instance.Blobs = blobs
	instance.CreatedAt = time.Now()

	return nil
}

// waitReady waits until the unit runs, the mount is in place and the API
// answers. The mount alone is not enough: it exists before the request
// workers start.
func (f *fileSystem) waitReady(ctx context.Context, d *Daemon) error {
	var notReady error
	err := readyBackoff.DelayFunc().Until(ctx, true, false, func(ctx context.Context) (bool, error) {
		state, err := f.systemd.ActiveState(ctx, d.Instance.Unit)
		if err != nil {
			return false, err
		}

		switch state {
		case systemd.ActiveStateActive:
			notReady = f.ready(ctx, d)
			return notReady == nil, nil
		case systemd.ActiveStateActivating:
			return false, nil
		default:
			return false, fmt.Errorf("unit %s is %s, see journalctl -u %s", d.Instance.Unit, state, d.Instance.Unit)
		}
	})

	// Tell why a daemon that never got ready was not.
	if err != nil && notReady != nil {
		return fmt.Errorf("%w: %w", err, notReady)
	}

	return err
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

// settledState waits out activating and deactivating states.
func (f *fileSystem) settledState(ctx context.Context, cfg *config.Config, unit string) (string, error) {
	var state string
	err := wait.PollUntilContextTimeout(ctx, pollInterval, time.Duration(cfg.Nydusd.MountTimeout), true, func(ctx context.Context) (bool, error) {
		var err error
		state, err = f.systemd.ActiveState(ctx, unit)
		return state != systemd.ActiveStateActivating && state != systemd.ActiveStateDeactivating, err
	})

	return state, err
}

// recordRunning records a running daemon found without its record, as after
// nydusd.db was lost.
func (f *fileSystem) recordRunning(instance *store.Instance, image *Image) error {
	if _, err := f.store.GetInstance(instance.ChainID); !errdefs.IsNotFound(err) {
		return err
	}

	ref, err := registry.ParseReference(image.Ref)
	if err != nil {
		return err
	}

	if err := f.describe(instance, ref, NewBootstrapLayer(image.BootstrapDir)); err != nil {
		return err
	}

	return f.store.PutInstance(instance)
}

// stop stops a daemon, detaches what its mount left behind and removes its
// files and record. The daemon unmounts on SIGTERM itself. Its logs stay, so
// a failed start can be read; teardown removes them.
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

	for _, path := range []string{filepath.Dir(d.Instance.Bootstrap), filepath.Dir(d.Config), d.Instance.APISocket} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}

	return f.store.DeleteInstance(d.Instance.ChainID)
}
