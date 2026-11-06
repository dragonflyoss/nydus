/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

func TestFuseDriver_Args(t *testing.T) {
	tests := []struct {
		name   string
		daemon *Daemon
		expect func(t *testing.T, args []string)
	}{
		{
			name: "nydus fuse arguments",
			daemon: &Daemon{
				Instance: &store.Instance{
					Bootstrap:  "/var/lib/containerd-nydus-v3/nydusd/ab/image.boot",
					Mountpoint: "/var/lib/containerd-nydus-v3/nydusd/ab/mnt",
					APISocket:  "/run/containerd-nydus-v3/nydusd/ab.sock",
				},
				Config: "/run/containerd-nydus-v3/nydusd/ab/config.yaml",
				LogDir: "/var/log/nydus-v3/nydusd/ab",
				id:     "abcdef0123456789",
			},
			expect: func(t *testing.T, args []string) {
				assert.Equal(t, []string{
					"fuse",
					"--bootstrap", "/var/lib/containerd-nydus-v3/nydusd/ab/image.boot",
					"--config", "/run/containerd-nydus-v3/nydusd/ab/config.yaml",
					"--mountpoint", "/var/lib/containerd-nydus-v3/nydusd/ab/mnt",
					"--apiserver", "unix:///run/containerd-nydus-v3/nydusd/ab.sock",
					"--log-dir", "/var/log/nydus-v3/nydusd/ab",
					"--fsname", "nydus-abcdef012345",
				}, args)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, (&fuseDriver{}).Args(tc.daemon))
		})
	}
}

func TestFuseDriver_Mounted(t *testing.T) {
	tests := []struct {
		name    string
		fstype  string
		mounts  int
		symlink bool
		expect  func(t *testing.T, mounted bool, err error)
	}{
		{
			name:   "fuse mount",
			fstype: "fuse",
			mounts: 1,
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(mounted)
			},
		},
		{
			name:    "fuse mount under a symlinked root",
			fstype:  "fuse",
			mounts:  1,
			symlink: true,
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(mounted)
			},
		},
		{
			name: "plain directory",
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(mounted)
			},
		},
		{
			name:   "mount of another file system",
			fstype: "tmpfs",
			mounts: 1,
			expect: func(t *testing.T, mounted bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(mounted)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, tc.fstype, tc.mounts)
			if tc.symlink {
				link := filepath.Join(t.TempDir(), "root")
				assert.NoError(t, os.Symlink(filepath.Dir(d.Instance.Mountpoint), link))
				d.Instance.Mountpoint = filepath.Join(link, filepath.Base(d.Instance.Mountpoint))
			}

			mounted, err := (&fuseDriver{}).Mounted(d)
			tc.expect(t, mounted, err)
		})
	}
}

func TestFuseDriver_Unmount(t *testing.T) {
	tests := []struct {
		name    string
		fstype  string
		mounts  int
		missing bool
		expect  func(t *testing.T, d *Daemon, err error)
	}{
		{
			name: "nothing mounted",
			expect: func(t *testing.T, d *Daemon, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:    "missing mountpoint",
			missing: true,
			expect: func(t *testing.T, d *Daemon, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:   "detach a fuse mount without a server",
			fstype: "fuse",
			mounts: 1,
			expect: func(t *testing.T, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				mounted, err := (&fuseDriver{}).Mounted(d)
				assert.NoError(err)
				assert.False(mounted)
			},
		},
		{
			name:   "detach stacked mounts",
			fstype: "tmpfs",
			mounts: 2,
			expect: func(t *testing.T, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				mounted, err := mountinfo.Mounted(d.Instance.Mountpoint)
				assert.NoError(err)
				assert.False(mounted)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, tc.fstype, tc.mounts)
			if tc.missing {
				assert.NoError(t, os.Remove(d.Instance.Mountpoint))
			}

			tc.expect(t, d, (&fuseDriver{}).Unmount(d))
		})
	}
}

func newTestDaemon(t *testing.T, fstype string, mounts int) *Daemon {
	t.Helper()
	mountpoint := filepath.Join(t.TempDir(), "mnt")
	assert.NoError(t, os.MkdirAll(mountpoint, 0o700))
	if mounts > 0 && os.Geteuid() != 0 {
		t.Skip("mounts as root")
	}

	for range mounts {
		switch fstype {
		case "fuse":
			fuse, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
			if err != nil {
				t.Skipf("open /dev/fuse: %v", err)
			}
			t.Cleanup(func() { fuse.Close() })

			options := fmt.Sprintf("fd=%d,rootmode=40000,user_id=0,group_id=0", fuse.Fd())
			assert.NoError(t, unix.Mount("nydus-test", mountpoint, "fuse.nydus-test", 0, options))
		default:
			assert.NoError(t, unix.Mount("tmpfs", mountpoint, "tmpfs", 0, ""))
		}
	}

	t.Cleanup(func() {
		for {
			if err := unix.Unmount(mountpoint, unix.MNT_DETACH); err != nil {
				return
			}
		}
	})

	return &Daemon{Instance: &store.Instance{Mountpoint: mountpoint}}
}
