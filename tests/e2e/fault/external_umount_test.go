package fault

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"golang.org/x/sys/unix"
)

// TestExternalUmount unmounts the image from outside the daemon, as an
// administrator or a container runtime cleaning up does. The FUSE daemon
// sees its session end and exits 0, leaving nothing behind; after a lazy
// unmount it keeps serving a file still open and exits once that closes.
// fileio keeps its backing export alive until explicitly signaled, including
// while a detached EROFS mount still has open files.
func TestExternalUmount(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	cases := []struct {
		name     string
		flags    int
		holdOpen bool
	}{
		{"umount", 0, false},
		{"lazy", unix.MNT_DETACH, false},
		{"lazy-open-file", unix.MNT_DETACH, true},
	}
	for _, c := range cases {
		t.Run("fuse/"+c.name, func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
			prime(t, m)
			kids := proc.Children(m.Daemon.Pid())
			big := lookup(t, img, bigFile)

			var held *os.File
			if c.holdOpen {
				f, err := os.Open(m.Path(big.Rel))
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				held = f
				defer func() { _ = held.Close() }()
			}
			if err := unix.Unmount(m.Root, c.flags); err != nil {
				t.Fatalf("unmount %s: %v", m.Root, err)
			}
			if held != nil {
				expectCorrect(t, judge(t, big, readTimeout, func() (string, error) { return hashFile(held) }))
				if !m.Daemon.Alive() {
					t.Errorf("the daemon exited while a file of its detached mount was open")
				}
				_ = held.Close()
			}

			mustExit(t, m.Daemon, exitTimeout, "its mount went away")
			if code := m.Daemon.ExitCode(); code != 0 {
				t.Errorf("want exit code 0 after an external unmount, got %d", code)
			}
			expectNoMounts(t, daemonDir(m), m.Root)
			expectGone(t, kids, exitTimeout)
		})
	}
	for _, c := range cases {
		t.Run("fileio/"+c.name, func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.Fileio{}, img, mount.Options{})
			prime(t, m)
			kids := proc.Children(m.Daemon.Pid())
			dir, points := daemonDir(m), mountpoints(m)
			big := lookup(t, img, bigFile)
			var held *os.File
			if c.holdOpen {
				f, err := os.Open(m.Path(big.Rel))
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				held = f
				defer func() { _ = held.Close() }()
			}
			if err := unix.Unmount(m.Root, c.flags); err != nil {
				t.Fatalf("unmount %s: %v", m.Root, err)
			}
			if mount.IsMountpoint(m.Root) {
				t.Fatal("EROFS mount still attached after external unmount")
			}
			if waitExit(m.Daemon, 5*time.Second) {
				t.Fatal("fileio exited after external unmount without an explicit shutdown")
			}
			if held != nil {
				expectCorrect(t, judge(t, big, readTimeout, func() (string, error) { return hashFile(held) }))
				if !m.Daemon.Alive() {
					t.Errorf("fileio exited while a file of its detached mount was open")
				}
				if err := held.Close(); err != nil {
					t.Fatalf("close detached file: %v", err)
				}
			}
			m.Daemon.Signal(syscall.SIGTERM)
			mustExit(t, m.Daemon, exitTimeout, "explicit shutdown after external unmount")
			if code := m.Daemon.ExitCode(); code != 0 {
				t.Errorf("want exit code 0 after explicit shutdown, got %d", code)
			}
			expectNoMounts(t, dir, points...)
			expectGone(t, kids, exitTimeout)
		})
	}
}
