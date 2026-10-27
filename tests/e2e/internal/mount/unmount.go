package mount

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// IsMountpoint reports whether path is currently a mountpoint.
func IsMountpoint(path string) bool {
	return exec.Command("mountpoint", "-q", path).Run() == nil
}

// Unmount detaches mnt, retrying while the kernel still holds references.
// A umount straight after heavy I/O routinely returns EBUSY for a moment, as
// does one racing a fork elsewhere in the test binary, and giving up there
// leaves a dead mountpoint that later trips up directory removal. The
// kernel's answer decides whether mnt is still mounted: mountinfo can miss
// entries while parallel tests mount and unmount. Without CAP_SYS_ADMIN,
// fusermount does the unmount instead. A lazy unmount is the last resort.
func Unmount(mnt string) {
	for range 50 {
		err := syscall.Unmount(mnt, 0)
		if err == nil || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
			return
		}
		if errors.Is(err, syscall.EPERM) {
			for _, bin := range []string{"fusermount3", "fusermount"} {
				_ = exec.Command(bin, "-u", mnt).Run()
				if !IsMountpoint(mnt) {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Unmount(mnt, syscall.MNT_DETACH)
}
