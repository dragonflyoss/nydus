/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

// reloadTimeout bounds applying the cgroup limits of a reloaded config.
const reloadTimeout = time.Minute

// Reload switches to a reloaded config: its cgroup limits apply now, the
// rest to daemons started later.
func (f *fileSystem) Reload(ctx context.Context, cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()

	f.cfg.Store(cfg)
	return f.applyCgroupLimits(ctx)
}

// applyCgroupLimits applies the cgroup limits of the current config: the
// slice's, then every daemon's. What is deferred or fails leaves
// limitsDeferred set, so Release retries it.
func (f *fileSystem) applyCgroupLimits(ctx context.Context) error {
	f.limitsMu.Lock()
	defer f.limitsMu.Unlock()

	cfg := f.cfg.Load()
	deferred, err := f.startDaemonSlice(ctx, cfg)
	if err == nil {
		err = f.limitDaemons(ctx, cfg)
	}
	f.limitsDeferred.Store(deferred || err != nil)

	return err
}

// startDaemonSlice starts the daemon slice with the total budget of cfg. It
// reports whether the limits were deferred: a memory.max below the current
// usage would OOM kill a daemon and break its containers for good, so the
// slice is left as it is until Release retries.
func (f *fileSystem) startDaemonSlice(ctx context.Context, cfg *config.Config) (bool, error) {
	total := systemd.Resources{
		MemoryMax:          uint64(cfg.Cgroup.MemoryMax),
		MemoryHigh:         uint64(cfg.Cgroup.MemoryHigh),
		CPUQuotaPerSecUSec: cfg.Cgroup.CPUQuota.PerSecUSec(),
	}

	slice := cfg.Cgroup.Slice
	if total.MemoryMax != 0 {
		current, err := f.systemd.MemoryCurrent(ctx, slice)
		if err != nil {
			return false, err
		}

		// systemd reports an unloaded slice's usage as infinity.
		if current != math.MaxUint64 && current > total.MemoryMax {
			log.G(ctx).WithFields(log.Fields{"slice": slice, "memory_max": total.MemoryMax, "memory_current": current}).Warn("memory_max is below the current usage, deferring the slice limits")
			return true, nil
		}
	}

	return false, f.systemd.StartSlice(ctx, slice, sliceDescription, total)
}

// limitDaemons applies the per-daemon limits of cfg to every daemon unit.
func (f *fileSystem) limitDaemons(ctx context.Context, cfg *config.Config) error {
	units, err := f.daemonUnits(ctx, cfg)
	if err != nil {
		return err
	}

	errs := make([]error, 0, len(units))
	for id := range units {
		errs = append(errs, f.systemd.SetResources(ctx, id.Unit(), f.daemonResources(cfg)))
	}

	return errors.Join(errs...)
}

// daemonResources returns the per-daemon cgroup limits. Memory uses
// memory.high only: a memory.max hit is an OOM kill, and FUSE cannot recover.
func (f *fileSystem) daemonResources(cfg *config.Config) systemd.Resources {
	return systemd.Resources{
		MemoryHigh:         uint64(cfg.Cgroup.Daemon.MemoryHigh),
		CPUQuotaPerSecUSec: cfg.Cgroup.Daemon.CPUQuota.PerSecUSec(),
	}
}
