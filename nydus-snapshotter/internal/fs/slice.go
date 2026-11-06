/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"math"

	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

// startSlices starts the daemon slice and its parent holding the total
// budget, with the limits of the current config. A memory.max below the
// current usage is deferred, since applying it would OOM kill a daemon and
// break its containers for good; teardown passes retry it.
func (f *fileSystem) startSlices(ctx context.Context) error {
	f.slicesMu.Lock()
	defer f.slicesMu.Unlock()

	cfg := f.cfg.Load()
	total := systemd.Resources{
		MemoryMax:          uint64(cfg.Cgroup.MemoryMax),
		MemoryHigh:         uint64(cfg.Cgroup.MemoryHigh),
		CPUQuotaPerSecUSec: cfg.Cgroup.CPUQuota.CPUQuotaPerSecUSec(),
	}

	parent := cfg.Cgroup.ParentSlice()
	if total.MemoryMax != 0 {
		current, err := f.systemd.MemoryCurrent(ctx, parent)
		if err != nil {
			return err
		}

		// systemd reports an unloaded slice's usage as infinity.
		if current != math.MaxUint64 && current > total.MemoryMax {
			log.G(ctx).WithFields(log.Fields{"slice": parent, "memory_max": total.MemoryMax, "memory_current": current}).Warn("memory_max is below the current usage, deferring the slice limits")
			f.limitsDeferred.Store(true)
			return nil
		}
	}

	if err := f.systemd.StartSlice(ctx, parent, total); err != nil {
		return err
	}
	f.limitsDeferred.Store(false)

	if parent == cfg.Cgroup.Slice {
		return nil
	}

	return f.systemd.StartSlice(ctx, cfg.Cgroup.Slice, systemd.Resources{})
}

// daemonResources returns the per-daemon cgroup limits. Memory uses
// memory.high only: a memory.max hit is an OOM kill, and FUSE cannot recover.
func (f *fileSystem) daemonResources(cfg *config.Config) systemd.Resources {
	return systemd.Resources{
		MemoryHigh:         uint64(cfg.Cgroup.Daemon.MemoryHigh),
		CPUQuotaPerSecUSec: cfg.Cgroup.Daemon.CPUQuota.CPUQuotaPerSecUSec(),
	}
}
