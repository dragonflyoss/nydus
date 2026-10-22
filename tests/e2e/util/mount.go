package util

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// HasMountOption reports whether the filesystem mounted at mountpoint carries the
// given mount option, as listed in /proc/self/mounts.
func HasMountOption(t *testing.T, mountpoint, option string) bool {
	t.Helper()
	mounts, err := os.ReadFile("/proc/self/mounts")
	assert.NoError(t, err)

	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == mountpoint {
			return slices.Contains(strings.Split(fields[3], ","), option)
		}
	}

	return false
}

// IsMountpoint reports whether path is currently a mountpoint.
func IsMountpoint(path string) bool {
	return exec.Command("mountpoint", "-q", path).Run() == nil
}

// MountFuse starts the prepared FUSE daemon cmd, waits for mountpoint to
// become a mountpoint and returns the cleanup that unmounts it and reaps the
// daemon. A daemon that does not start or mount stops the test, since
// nothing after a mount works without it.
func MountFuse(t *testing.T, cmd *exec.Cmd, mountpoint, label string) func() {
	t.Helper()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if !assert.NoError(t, cmd.Start()) {
		t.FailNow()
	}

	cleanup := func() {
		Unmount(mountpoint)

		// Ask the daemon to exit and give it a moment before killing it.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}

	// nydusify mount pulls the image before it mounts, so allow for a cold
	// registry.
	if !assert.Eventually(t, func() bool {
		return IsMountpoint(mountpoint)
	}, 30*time.Second, 200*time.Millisecond, "%s failed to mount within 30s", label) {
		cleanup()
		t.FailNow()
	}

	return cleanup
}

// MountNydusBlob runs `nydus fuse --blob` on a self-contained blob and
// returns the cleanup that unmounts it.
func MountNydusBlob(t *testing.T, nydusBin, blob, mountpoint string) func() {
	t.Helper()
	Unmount(mountpoint)
	assert.NoError(t, os.MkdirAll(mountpoint, 0o755))

	cmd := exec.Command(nydusBin, "fuse", "--blob", blob, "--mountpoint", mountpoint)
	return MountFuse(t, cmd, mountpoint, "nydus fuse")
}

// MountNydusBootstrap runs `nydus fuse --bootstrap` with a blob directory,
// enabling the persistent chunk cache under cacheDir when it is not empty,
// and returns the cleanup that unmounts it.
func MountNydusBootstrap(t *testing.T, nydusBin, bootstrap, blobDir, cacheDir, mountpoint string) func() {
	t.Helper()
	Unmount(mountpoint)
	assert.NoError(t, os.MkdirAll(mountpoint, 0o755))

	args := []string{"fuse", "--bootstrap", bootstrap, "--blob-dir", blobDir, "--mountpoint", mountpoint}
	if cacheDir != "" {
		assert.NoError(t, os.MkdirAll(cacheDir, 0o755))
		args = append(args, "--cache-dir", cacheDir)
	}

	return MountFuse(t, exec.Command(nydusBin, args...), mountpoint, "nydus fuse")
}

// MountErofsFuse mounts the EROFS image with the C erofsfuse binary and the
// given blob devices, and returns the cleanup that unmounts it.
func MountErofsFuse(t *testing.T, erofsFuseBin, image, mountpoint string, devices ...string) func() {
	t.Helper()
	Unmount(mountpoint)
	assert.NoError(t, os.MkdirAll(mountpoint, 0o755))

	args := make([]string, 0, len(devices)+3)
	for _, device := range devices {
		if device != "" {
			args = append(args, "--device="+device)
		}
	}
	args = append(args, image, mountpoint, "-f")

	return MountFuse(t, exec.Command(erofsFuseBin, args...), mountpoint, "erofsfuse")
}

// Unmount detaches mountpoint, retrying while the kernel still holds references: a
// umount straight after heavy I/O routinely returns EBUSY for a moment, and
// giving up there leaves a dead mountpoint that trips up directory removal.
// Without CAP_SYS_ADMIN, fusermount does the unmount instead.
func Unmount(mountpoint string) {
	for range 50 {
		err := syscall.Unmount(mountpoint, 0)
		if err == nil || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
			return
		}

		if errors.Is(err, syscall.EPERM) {
			for _, fusermount := range []string{"fusermount3", "fusermount"} {
				_ = exec.Command(fusermount, "-u", mountpoint).Run()
				if !IsMountpoint(mountpoint) {
					return
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	_ = exec.Command("umount", "-l", mountpoint).Run()
}

// MountErofsLoop attaches image and every device to read-only loop devices,
// mounts image with the kernel EROFS driver and returns the mountpoint. The
// cleanup unmounts it and detaches the loop devices; when the unmount fails
// the loop devices are retained and reported, since detaching a device still
// in use would fail anyway.
func MountErofsLoop(t *testing.T, image string, devices ...string) string {
	t.Helper()
	mountpoint := filepath.Join(t.TempDir(), "mountpoint")
	assert.NoError(t, os.Mkdir(mountpoint, 0o755))

	mounted := false
	attach := func(path string) string {
		out, err := exec.Command("losetup", "--find", "--show", "--read-only", path).CombinedOutput()
		assert.NoError(t, err, "attach %s: %s", path, out)
		device := strings.TrimSpace(string(out))
		t.Cleanup(func() {
			if mounted {
				t.Errorf("retaining %s because native mount cleanup failed", device)
				return
			}

			out, err := exec.Command("losetup", "--detach", device).CombinedOutput()
			assert.NoError(t, err, "detach %s: %s", device, out)
		})

		return device
	}

	// Mount the primary device with every blob device passed as a device=
	// option; the test cannot go on without the mount.
	primary := attach(image)
	options := []string{"ro"}
	for _, path := range devices {
		options = append(options, "device="+attach(path))
	}
	out, err := exec.Command("mount", "-t", "erofs", "-o", strings.Join(options, ","), primary, mountpoint).CombinedOutput()
	if !assert.NoError(t, err, "native EROFS mount: %s", out) {
		t.FailNow()
	}
	mounted = true
	t.Cleanup(func() {
		if err := syscall.Unmount(mountpoint, 0); err != nil {
			t.Errorf("unmount native EROFS %s: %v", mountpoint, err)
			return
		}
		mounted = false
	})

	return mountpoint
}
