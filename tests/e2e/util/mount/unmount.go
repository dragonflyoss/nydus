package mount

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// IsMountpoint reports whether path is currently a mountpoint, asking the
// kernel (statx) first and mountinfo only as a fallback.
func IsMountpoint(path string) bool {
	mounted, err := mountinfo.Mounted(path)
	return err == nil && mounted
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
		err := unix.Unmount(mnt, 0)
		if err == nil || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
			return
		}

		if errors.Is(err, unix.EPERM) {
			for _, bin := range []string{"fusermount3", "fusermount"} {
				_ = exec.Command(bin, "-u", mnt).Run()

				if !IsMountpoint(mnt) {
					return
				}
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	_ = unix.Unmount(mnt, unix.MNT_DETACH)
}

// PointsUnder lists the mountpoints at or below dir.
func PointsUnder(dir string) ([]string, error) {
	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(dir))
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(mounts))

	for _, m := range mounts {
		out = append(out, m.Mountpoint)
	}

	return out, nil
}

// ExpectNoMounts fails t if anything is still mounted at or below dir, and
// unmounts what it finds. mountinfo can miss an entry while parallel tests
// mount and unmount, so the directories directly under dir, where adapters
// put their mountpoints, are also asked of the kernel; a dead FUSE mount
// fails stat and only shows up in mountinfo.
func ExpectNoMounts(t testing.TB, dir string) {
	t.Helper()
	left, err := PointsUnder(dir)
	if err != nil {
		t.Fatalf("list mounts: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); e.IsDir() && IsMountpoint(p) && !slices.Contains(left, p) {
			left = append(left, p)
		}
	}

	if len(left) > 0 {
		t.Errorf("mounts left behind under %s: %v", dir, left)

		for _, p := range left {
			Unmount(p)
		}
	}
}
