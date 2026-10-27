package contract

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C15: a mount comes and goes cleanly: remounts give the same inode numbers,
// SIGTERM unmounts and exits 0, and an unmount while files are open or mapped
// is refused or, when lazy, leaves those references working.
func init() {
	Register(Case{ID: "C15", Name: "Lifecycle", Scope: Own, RunOwn: runLifecycle})
}

// exitTimeout bounds how long a daemon may take to exit once told to.
const exitTimeout = 15 * time.Second

func runLifecycle(t *testing.T, a mount.Adapter) {
	img := SemanticImage(t)
	ownsMount := mount.TraitsOf(a).OwnsMount

	t.Run("RemountStability", func(t *testing.T) {
		t.Parallel()
		// Inode numbers derive from the on-disk NID, so they must survive
		// unmount/remount cycles unchanged.
		var first map[string]uint64
		for cycle := range 3 {
			m := mount.Mount(t, a, img, mount.Options{})
			inodes := inodeMap(t, m.Root)
			m.Unmount()
			require.False(t, mount.IsMountpoint(m.Root), "cycle %d: still mounted", cycle)
			require.Zero(t, m.Daemon.ExitCode(), "cycle %d: daemon exit code", cycle)
			if first == nil {
				first = inodes
				continue
			}
			require.Equal(t, first, inodes, "cycle %d: inode numbers changed across a remount", cycle)
		}
	})

	t.Run("SIGTERM", func(t *testing.T) {
		t.Parallel()
		m := mount.Mount(t, a, img, mount.Options{})
		mount.ReadAll(t, m.Path("files"))
		if !ownsMount {
			// The daemon serves the device its caller mounted; stopping it
			// under a live mount is not a supported sequence.
			mount.Unmount(m.Root)
		}
		m.Daemon.Signal(syscall.SIGTERM)
		waitExit(t, m.Daemon)
		require.Zero(t, m.Daemon.ExitCode(), "exit code after SIGTERM")
		// Nothing the daemon mounted (fileio also mounts its export) is left.
		mounts, err := proc.MountsUnder(filepath.Dir(m.Root))
		require.NoError(t, err)
		require.Empty(t, mounts, "mounts left behind after SIGTERM")
	})

	t.Run("UnmountWithOpenFile", func(t *testing.T) {
		t.Parallel()
		m := mount.Mount(t, a, img, mount.Options{})
		f := &Fixture{Mounted: m, Adapter: a}
		rel := "files/large_256k"
		want := wantBytes(t, f, rel)
		// Not openRO: this test closes the descriptor itself, and a second
		// close from a cleanup could hit a number a parallel test reused.
		fd, err := unix.Open(m.Path(rel), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		open := true
		t.Cleanup(func() {
			if open {
				_ = unix.Close(fd)
			}
		})
		buf := make([]byte, len(want))
		n, err := unix.Pread(fd, buf[:4096], 0)
		require.NoError(t, err)
		require.True(t, bytes.Equal(want[:n], buf[:n]))

		require.ErrorIs(t, unix.Unmount(m.Root, 0), unix.EBUSY, "unmount with an open file")
		require.True(t, mount.IsMountpoint(m.Root))

		// A lazy unmount detaches the mount at once; the open file keeps
		// reading, from the daemon rather than the page cache.
		require.NoError(t, unix.Unmount(m.Root, unix.MNT_DETACH))
		require.False(t, mount.IsMountpoint(m.Root), "still mounted after a lazy unmount")
		require.True(t, m.Daemon.Alive(), "the daemon exited while a file was still open")
		require.NoError(t, unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED))
		n, err = unix.Pread(fd, buf, 0)
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, buf[:n]), "reading an open file after a lazy unmount")
		open = false
		require.NoError(t, unix.Close(fd))

		if !ownsMount {
			require.True(t, m.Daemon.Alive(), "the daemon exited when its caller's mount went away")
		}
		// Detaching the mount does not request shutdown of its backing
		// service. Explicitly stop it after releasing the last reference.
		m.Daemon.Signal(syscall.SIGTERM)
		waitExit(t, m.Daemon)
		require.Zero(t, m.Daemon.ExitCode(), "exit code after explicit shutdown")
	})

	t.Run("LazyUnmountWithClosedFDMmap", func(t *testing.T) {
		t.Parallel()
		m := mount.Mount(t, a, img, mount.Options{})
		f := &Fixture{Mounted: m, Adapter: a}
		rel := "files/large_256k"
		want := wantBytes(t, f, rel)
		fd, err := unix.Open(m.Path(rel), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		open := true
		t.Cleanup(func() {
			if open {
				require.NoError(t, unix.Close(fd))
			}
		})
		// Do not fault any pages before detaching: the first read must be
		// served while only the mapping, not a descriptor, pins the mount.
		data, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ, unix.MAP_PRIVATE)
		require.NoError(t, err)
		mapped := true
		t.Cleanup(func() {
			if mapped {
				require.NoError(t, unix.Munmap(data))
			}
		})
		require.NoError(t, unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED))
		open = false
		require.NoError(t, unix.Close(fd))

		require.ErrorIs(t, unix.Unmount(m.Root, 0), unix.EBUSY, "unmount with a live mapping")
		require.True(t, mount.IsMountpoint(m.Root))
		require.NoError(t, unix.Unmount(m.Root, unix.MNT_DETACH))
		require.False(t, mount.IsMountpoint(m.Root), "still mounted after a lazy unmount")
		// Allow asynchronous shutdown detection to run before faulting.
		select {
		case <-m.Daemon.Exited():
			t.Fatal("the daemon exited while a mapping still referenced the detached mount")
		case <-time.After(time.Second):
		}
		require.True(t, bytes.Equal(want, data), "reading a mapping after closing its fd and detaching")
		require.True(t, m.Daemon.Alive(), "the daemon exited while a mapping was still live")
		require.NoError(t, unix.Munmap(data))
		mapped = false

		m.Daemon.Signal(syscall.SIGTERM)
		waitExit(t, m.Daemon)
		require.Zero(t, m.Daemon.ExitCode(), "exit code after explicit shutdown")
	})
}

// waitExit waits for d to exit by itself.
func waitExit(t env.TB, d *mount.Daemon) {
	t.Helper()
	select {
	case <-d.Exited():
	case <-time.After(exitTimeout):
		t.Fatalf("%s still running %s later", d.Name, exitTimeout)
	}
}

// inodeMap maps every path under root to its inode number.
func inodeMap(t *testing.T, root string) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	require.NoError(t, filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		out[rel] = st.Ino
		return nil
	}))
	return out
}
