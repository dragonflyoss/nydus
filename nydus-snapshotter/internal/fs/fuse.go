/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

// fuseDriver mounts an image with nydus fuse, refer to the Fuse section of
// docs/nydus.md.
type fuseDriver struct{}

// Name returns the driver name recorded in instances.
func (*fuseDriver) Name() string {
	return config.DriverFuse
}

// Args returns the daemon's arguments after the nydus binary.
func (*fuseDriver) Args(d *Daemon) []string {
	instance := d.Instance
	return []string{
		"fuse",
		"--bootstrap", instance.Bootstrap,
		"--config", d.Config,
		"--mountpoint", instance.Mountpoint,
		"--apiserver", "unix://" + instance.APISocket,
		"--log-dir", d.LogDir,
		"--fsname", "nydus-" + d.id.Short(),
	}
}

// Environment returns the daemon's KEY=VALUE variables. The console log is
// off: it duplicates the --log-dir files with terminal colors.
func (*fuseDriver) Environment() []string {
	return []string{"NYDUS_FUSE_CONSOLE=false"}
}

// Mounted reports whether the daemon's mount is in place. mountinfo lists
// resolved paths, so the mountpoint's parent is resolved first, as
// containerd's mount.Lookup does; never the mountpoint itself, whose lstat
// fails or hangs on a dead FUSE server, refer to
// https://github.com/containerd/containerd/blob/main/core/mount/lookup_unix.go.
func (*fuseDriver) Mounted(d *Daemon) (bool, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(d.Instance.Mountpoint))
	if err != nil {
		return false, fmt.Errorf("resolve mountpoint: %w", err)
	}

	mountpoint := filepath.Join(parent, filepath.Base(d.Instance.Mountpoint))
	mounts, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(mountpoint))
	if err != nil {
		return false, fmt.Errorf("read mountinfo: %w", err)
	}

	for _, m := range mounts {
		if m.FSType == "fuse" || strings.HasPrefix(m.FSType, "fuse.") {
			return true, nil
		}
	}

	return false, nil
}

// Unmount detaches what the daemon's mount left behind once the daemon
// stopped, a stale mount included; an absent mount is not an error. A lazy
// detach never blocks on a dead FUSE server.
func (*fuseDriver) Unmount(d *Daemon) error {
	// Detach every stacked mount, until none is left.
	for {
		err := unix.Unmount(d.Instance.Mountpoint, unix.MNT_DETACH)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("unmount %s: %w", d.Instance.Mountpoint, err)
		}
	}
}
