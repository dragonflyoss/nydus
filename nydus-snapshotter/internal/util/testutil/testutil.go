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
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

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
	cfg.Root = filepath.Join(dir, "lib")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.Address = filepath.Join(cfg.RunDir, "s.sock")
	cfg.Metrics.Address = "127.0.0.1:0"
	cfg.Nydusd.LogDir = filepath.Join(dir, "log")
	cfg.Cgroup.Slice = "nydustest" + strconv.Itoa(os.Getpid()) + strconv.Itoa(rand.IntN(1<<30)) + ".slice"
	// A test that started no slice has none to stop.
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", cfg.Cgroup.Slice).Run() })
	return cfg
}
