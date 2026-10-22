// Package nbd serves images through `nydus nbd`: the flattened image is
// exported as /dev/nbdX and the daemon mounts it with the kernel EROFS
// driver.
package nbd

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"golang.org/x/sys/unix"
)

const (
	daemonName = "nydus-nbd"
	// mountTimeout bounds how long the daemon may take to attach and mount.
	mountTimeout = 90 * time.Second
	// deviceWait bounds how long a mount waits for a free /dev/nbdX while
	// parallel tests hold them all.
	deviceWait = 2 * time.Minute
	// releaseTimeout bounds how long the kernel may take to detach a device
	// after its daemon exited.
	releaseTimeout = 10 * time.Second
)

// NBD serves an image through `nydus nbd`.
type NBD struct{}

func (NBD) Name() string { return "nbd" }

func (NBD) Require(t env.TB) {
	t.Helper()
	env.RequireRoot(t)
	env.RequireKernel(t, 6, 4, "EROFS flatdev mounts of a flattened image")
	env.RequireFilesystem(t, "erofs")
	env.Require(t, loadModule(), "nbd kernel module unavailable (modprobe nbd)")
	requireSubcommand(t, "nbd")
}

// Supports reports Cold and Warm: the flattened device needs a bootstrap.
func (NBD) Supports(m mount.Mode) bool { return m != mount.Blob }

// Traits: the daemon mounts EROFS itself but serves no apiserver.
func (NBD) Traits() mount.Traits { return mount.Traits{API: false, OwnsMount: true} }

func (NBD) Start(t env.TB, req mount.Request) (string, *mount.Daemon, func()) {
	t.Helper()
	mnt := filepath.Join(req.Dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("create %s: %v", mnt, err)
	}
	dev := acquireDevice(t)
	// Registered before the daemon so it runs after the daemon stopped.
	t.Cleanup(func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	})
	args := []string{"nbd",
		"--bootstrap", req.Image.Bootstrap,
		"--config", req.Config,
		"--device", dev.path,
		"--mountpoint", mnt,
	}
	d := mount.StartDaemon(t, req.Dir, daemonName, env.Nydus(t), mount.DaemonArgs(args, req, daemonName)...)
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool {
		return mount.IsMountpoint(mnt) && strings.Contains(d.Log(), "mounted "+dev.path)
	})
	return mnt, d, func() {
		// The daemon unmounts before it disconnects the device; the fallback
		// only matters when it died without running its shutdown path.
		d.Stop()
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
		dev.release(t)
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

// loadModule loads the nbd module unless its devices already exist.
func loadModule() bool {
	if _, err := os.Stat("/sys/block/nbd0"); err == nil {
		return true
	}
	_ = exec.Command("modprobe", "nbd").Run()
	_, err := os.Stat("/sys/block/nbd0")
	return err == nil
}

// device is an /dev/nbdX held by one daemon. A flock on a per-device lock
// file keeps parallel tests, and other test binaries, off it until the
// kernel has detached it again.
type device struct {
	path  string
	sysfs string
	lock  *os.File
	once  sync.Once
}

var lockDir = sync.OnceValue(func() string {
	for _, dir := range []string{"/run/lock", os.TempDir()} {
		d := filepath.Join(dir, "nydus-e2e-nbd")
		if os.MkdirAll(d, 0o755) == nil {
			return d
		}
	}
	return os.TempDir()
})

// acquireDevice locks a free /dev/nbdX for the test, waiting while every
// device is busy. It is released when the test ends, after the daemon.
func acquireDevice(t env.TB) *device {
	t.Helper()
	deadline := time.Now().Add(deviceWait)
	for {
		if d := tryAcquire(); d != nil {
			t.Cleanup(func() { d.release(t) })
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("no free NBD device within %s", deviceWait)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func tryAcquire() *device {
	paths, _ := filepath.Glob("/sys/block/nbd*")
	sort.Slice(paths, func(i, j int) bool { return nbdIndex(paths[i]) < nbdIndex(paths[j]) })
	for _, sysfs := range paths {
		name := filepath.Base(sysfs)
		lock, err := os.OpenFile(filepath.Join(lockDir(), name+".lock"), os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			continue
		}
		if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			_ = lock.Close()
			continue
		}
		d := &device{path: "/dev/" + name, sysfs: sysfs, lock: lock}
		if _, err := os.Stat(d.path); err != nil || !d.free() {
			_ = lock.Close()
			continue
		}
		return d
	}
	return nil
}

func nbdIndex(sysfs string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(sysfs), "nbd"))
	return n
}

// free reports whether the kernel has the device detached (size 0).
func (d *device) free() bool {
	data, err := os.ReadFile(filepath.Join(d.sysfs, "size"))
	return err != nil || strings.TrimSpace(string(data)) == "0"
}

// release waits for the kernel to detach the device and unlocks it. A
// device still attached stays locked, so no later test reuses it.
func (d *device) release(t env.TB) {
	d.once.Do(func() {
		deadline := time.Now().Add(releaseTimeout)
		for !d.free() {
			if time.Now().After(deadline) {
				t.Errorf("%s still attached %s after its daemon stopped", d.path, releaseTimeout)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		_ = d.lock.Close()
	})
}
