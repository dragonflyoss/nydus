package util

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// PageCacheMiB returns the kernel's total page cache from /proc/meminfo in MiB,
// -1 when the Cached line is missing.
//
// Serving one byte can cache it more than once: the daemon's own copy of the
// blob cache file, an intermediate object (the FUSE export, a block device),
// and finally the inode the application reads. Growth across a cold read of a
// known size is the cheapest way to see how many of those copies survive.
func PageCacheMiB(t *testing.T) float64 {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	assert.NoError(t, err)

	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "Cached:")
		if !ok {
			continue
		}

		var kb float64
		if _, err := fmt.Sscanf(rest, "%f kB", &kb); err == nil {
			return kb / 1024
		}
	}

	return -1
}

// DropCaches flushes dirty pages and drops the page cache, dentries and
// inodes, so the next read is served from the backing store.
func DropCaches(t *testing.T) {
	t.Helper()
	syscall.Sync()
	assert.NoError(t, os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o644))

	// Give the kernel a moment to finish dropping before the test goes on.
	time.Sleep(500 * time.Millisecond)
}

// KernelVersion returns the major and minor version of the running kernel.
func KernelVersion(t *testing.T) (int, int) {
	t.Helper()
	var uts syscall.Utsname
	assert.NoError(t, syscall.Uname(&uts))

	release := make([]byte, 0, len(uts.Release))
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}

	parts := strings.SplitN(string(release), ".", 3)
	assert.GreaterOrEqual(t, len(parts), 2, "unexpected kernel release: %s", release)
	major, err := strconv.Atoi(parts[0])
	assert.NoError(t, err)
	minor, err := strconv.Atoi(strings.TrimRightFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	assert.NoError(t, err)

	return major, minor
}

// ErofsSupported reports whether the running kernel has EROFS support, built
// in or as a module.
func ErofsSupported() bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}

	return strings.Contains(string(data), "\terofs\n")
}

// IsCharDevice reports whether fd refers to a character device, such as
// /dev/zero.
func IsCharDevice(t *testing.T, fd int) bool {
	t.Helper()
	var st unix.Stat_t
	assert.NoError(t, unix.Fstat(fd, &st))
	return st.Mode&unix.S_IFMT == unix.S_IFCHR
}

// FindFreeNbdDevice returns an unattached /dev/nbdX, loading the nbd module
// when no device exists yet.
func FindFreeNbdDevice() (string, error) {
	if _, err := os.Stat("/dev/nbd0"); err != nil {
		if exec.Command("modprobe", "nbd").Run() != nil {
			return "", fmt.Errorf("nbd module not available and modprobe failed: %w", err)
		}
	}

	// A device whose sysfs size is zero has no server attached.
	for i := range 16 {
		dev := fmt.Sprintf("/dev/nbd%d", i)
		if _, err := os.Stat(dev); err != nil {
			continue
		}

		data, err := os.ReadFile(fmt.Sprintf("/sys/block/nbd%d/size", i))
		if err == nil && strings.TrimSpace(string(data)) == "0" {
			return dev, nil
		}
	}

	return "", errors.New("no free /dev/nbdX device (nbd0-nbd15 all in use)")
}

// WaitNbdDetached waits until the kernel reports the NBD device as
// detached, its sysfs size back to zero.
func WaitNbdDetached(t *testing.T, device string) {
	t.Helper()
	sysfs := filepath.Join("/sys/block", filepath.Base(device), "size")
	assert.Eventually(t, func() bool {
		data, err := os.ReadFile(sysfs)
		return err != nil || strings.TrimSpace(string(data)) == "0"
	}, 10*time.Second, 100*time.Millisecond, "NBD device %s not released after daemon exit", device)
}
