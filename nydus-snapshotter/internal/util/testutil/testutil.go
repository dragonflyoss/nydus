/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package testutil holds the helpers tests of several packages share, as
// containerd's pkg/testutil does, refer to
// https://github.com/containerd/containerd/blob/main/pkg/testutil/helpers.go.
package testutil

import (
	"errors"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

// RequireSystemd skips a test that cannot talk to systemd: it needs root and
// systemd as init, told as sd_booted(3) tells it.
func RequireSystemd(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("talks to systemd as root")
	}

	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("needs systemd as init")
	}
}

// NewConfig returns the config of a test that runs the snapshotter: its
// paths live in a temp dir and its daemons get a slice of their own, stopped
// when the test ends. It skips a test that cannot talk to systemd.
func NewConfig(t *testing.T) *config.Config {
	t.Helper()
	RequireSystemd(t)
	dir := t.TempDir()
	cfg := config.New()
	cfg.RootDir = filepath.Join(dir, "lib")
	cfg.RuntimeDir = filepath.Join(dir, "run")
	cfg.GRPC.Addr = filepath.Join(cfg.RuntimeDir, "s.sock")
	cfg.Metrics.Addr = "127.0.0.1:0"
	cfg.Nydusd.LogDir = filepath.Join(dir, "log")
	cfg.Cgroup.Slice = "nydustest" + strconv.Itoa(os.Getpid()) + strconv.Itoa(rand.IntN(1<<30)) + ".slice"
	// A test that started no slice has none to stop.
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", cfg.Cgroup.Slice).Run() })
	return cfg
}

// MountTmpfs mounts a tmpfs with options on dir, created when missing, and
// unmounts it when the test ends. It skips a test that may not mount: one
// not run as root, or as root without CAP_SYS_ADMIN as in a container.
func MountTmpfs(t *testing.T, dir, options string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounts as root")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	err := unix.Mount("tmpfs", dir, "tmpfs", 0, options)
	if errors.Is(err, unix.EPERM) {
		t.Skip("mounts with CAP_SYS_ADMIN")
	}

	if err != nil {
		t.Fatalf("mount tmpfs on %s: %v", dir, err)
	}

	t.Cleanup(func() {
		if err := unix.Unmount(dir, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount %s: %v", dir, err)
		}
	})
}
