// Package ublk serves images through `nydus ublk`: the flattened image is
// exported as a /dev/ublkbN block device that the caller mounts with the
// kernel EROFS driver.
package ublk

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

const (
	daemonName = "nydus-ublk"
	// startTimeout bounds how long the daemon may take to create its device.
	startTimeout = 60 * time.Second
)

// Ublk serves an image through `nydus ublk`.
type Ublk struct{}

func (Ublk) Name() string { return "ublk" }

func (Ublk) Require(t env.TB) {
	t.Helper()
	env.RequireRoot(t)
	env.RequireKernel(t, 6, 4, "EROFS flatdev mounts of a flattened image")
	env.RequireFilesystem(t, "erofs")
	err := loadDriver()
	env.Require(t, err == nil, "ublk driver unavailable: %v", err)
	requireSubcommand(t, "ublk")
}

// Supports reports Cold and Warm: the flattened device needs a bootstrap.
func (Ublk) Supports(m mount.Mode) bool { return m != mount.Blob }

// Traits: the daemon serves metrics but only exports the device; the
// adapter mounts it.
func (Ublk) Traits() mount.Traits { return mount.Traits{API: true, OwnsMount: false} }

func (Ublk) Start(t env.TB, req mount.Request) (string, *mount.Daemon, func()) {
	t.Helper()
	args := mount.DaemonArgs([]string{"ublk",
		"--bootstrap", req.Image.Bootstrap,
		"--config", req.Config,
		"--apiserver", "unix://" + req.Socket,
	}, req, daemonName)
	d := mount.StartDaemon(t, req.Dir, daemonName, env.Nydus(t), args...)
	var dev string
	d.WaitFor(t, startTimeout, "a ublk device", func() bool {
		dev = devicePath(d.Log())
		_, err := os.Stat(dev)
		return dev != "" && err == nil
	})

	mnt := filepath.Join(req.Dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("create %s: %v", mnt, err)
	}
	// The daemon serves the I/O of its own device, so the mount must go
	// before the daemon does: registered after the daemon, this cleanup
	// runs first.
	t.Cleanup(func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	})
	if out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", dev, mnt).CombinedOutput(); err != nil {
		t.Fatalf("mount %s at %s: %v\n%s", dev, mnt, err, out)
	}
	return mnt, d, func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
		d.Stop()
	}
}

// devicePattern matches the device path the daemon prints on stdout once
// the device is live, among its console log lines.
var devicePattern = regexp.MustCompile(`(?m)^(/dev/ublkb[0-9]+)\s*$`)

// devicePath returns the device the daemon reported in log, if any.
func devicePath(log string) string {
	if m := devicePattern.FindStringSubmatch(log); m != nil {
		return m[1]
	}
	return ""
}

// loadDriver loads ublk_drv unless its control device already exists.
func loadDriver() error {
	if _, err := os.Stat("/dev/ublk-control"); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if out, err := exec.Command("modprobe", "ublk_drv").CombinedOutput(); err != nil {
		return fmt.Errorf("modprobe ublk_drv: %w\n%s", err, out)
	}
	// Module initialization can finish before userspace creates the device.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := os.Stat("/dev/ublk-control")
		if err == nil {
			return nil
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			return fmt.Errorf("control device after modprobe ublk_drv: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

var subcommands sync.Map

// requireSubcommand requires a nydus binary built with the feature that
// provides the subcommand.
func requireSubcommand(t env.TB, name string) {
	t.Helper()
	nydus := env.Nydus(t)
	ok, cached := subcommands.Load(name)
	if !cached {
		ok = exec.Command(nydus, name, "--help").Run() == nil
		subcommands.Store(name, ok)
	}
	env.Require(t, ok.(bool), "%s lacks the %s subcommand (build with FEATURES=...,%s)", nydus, name, name)
}
