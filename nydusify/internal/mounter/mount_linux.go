//go:build linux

/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package mounter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func prepareMountpoint(path string) (string, error) {
	mountpoint, err := filepath.Abs(path)
	if err != nil {
		return "", errors.Wrap(err, "resolve mountpoint")
	}
	mountpoint, err = filepath.EvalSymlinks(mountpoint)
	if err != nil {
		return "", errors.Wrap(err, "resolve mountpoint")
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", errors.Wrap(err, "inspect mountpoint")
	}
	escaped := strings.NewReplacer("\\", "\\134", " ", "\\040", "\t", "\\011", "\n", "\\012").Replace(mountpoint)
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == escaped {
			return "", errors.Errorf("mountpoint %q is already mounted", mountpoint)
		}
	}
	return mountpoint, nil
}

// Pin the mount before inspecting ownership: resolving its pathname again
// could unmount a replacement installed by another process.
func unmountExitedFuse(mountpoint, fsname string) error {
	fd, err := unix.Open(mountpoint, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); !errors.Is(err, unix.ENOTCONN) {
		return nil
	}
	fdinfo, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return err
	}
	var mountID string
	for _, line := range strings.Split(string(fdinfo), "\n") {
		if value, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			mountID = strings.TrimSpace(value)
		}
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(mountinfo), "\n") {
		if mountID == "" || !strings.HasPrefix(line, mountID+" ") {
			continue
		}
		_, filesystem, _ := strings.Cut(line, " - ")
		fields := strings.Fields(filesystem)
		if len(fields) >= 2 && fields[1] == fsname {
			// Do not pass the pathname to fusermount: its canonicalization
			// would lose the pinned mount identity. Forced cleanup needs CAP_SYS_ADMIN.
			return errors.Wrapf(unix.Unmount(fmt.Sprintf("/proc/self/fd/%d", fd), unix.MNT_DETACH), "unmount %q", mountpoint)
		}
	}
	return errors.Errorf("refusing to unmount %q: mount ownership changed", mountpoint)
}
