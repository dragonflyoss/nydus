package conformance

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testLifecycle(t *testing.T, a mount.Adapter) {
	img := semanticImage(t)
	ownsMount := mount.TraitsOf(a).OwnsMount

	t.Run("RemountStability", func(t *testing.T) {
		t.Parallel()
		var first map[string]uint64

		for range 3 {
			m := mount.Mount(t, a, img, mount.Options{})
			inodes := inodeMap(t, m.Root)
			m.Unmount()

			if !assert.False(t, mount.IsMountpoint(m.Root)) {
				t.FailNow()
			}
			if !assert.Zero(t, m.Daemon.ExitCode()) {
				t.FailNow()
			}

			if first == nil {
				first = inodes
				continue
			}

			assert.Equal(t, first, inodes)
		}
	})

	t.Run("SIGTERM", func(t *testing.T) {
		t.Parallel()
		m := mount.Mount(t, a, img, mount.Options{})
		mount.ReadAll(t, m.Path("files"))

		if !ownsMount {
			mount.Unmount(m.Root)
		}

		m.Daemon.Signal(unix.SIGTERM)

		if !assert.True(t, m.Daemon.WaitExit(exitTimeout)) {
			t.FailNow()
		}
		if !assert.Zero(t, m.Daemon.ExitCode()) {
			t.FailNow()
		}

		mount.ExpectNoMounts(t, m.Dir)
	})

	t.Run("UnmountWithOpenFile", func(t *testing.T) {
		t.Parallel()
		m := &mounted{Mounted: mount.Mount(t, a, img, mount.Options{}), adapter: a}
		rel := "files/large_256k"
		want := m.wantBytes(t, rel)
		fd, err := unix.Open(m.Path(rel), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		open := true

		t.Cleanup(func() {
			if open {
				_ = unix.Close(fd)
			}
		})

		buf := make([]byte, len(want))
		n, err := unix.Pread(fd, buf[:4096], 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.True(t, bytes.Equal(want[:n], buf[:n])) {
			t.FailNow()
		}
		if !assert.ErrorIs(t, unix.Unmount(m.Root, 0), unix.EBUSY) {
			t.FailNow()
		}
		if !assert.True(t, mount.IsMountpoint(m.Root)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Unmount(m.Root, unix.MNT_DETACH)) {
			t.FailNow()
		}
		if !assert.False(t, mount.IsMountpoint(m.Root)) {
			t.FailNow()
		}
		if !assert.True(t, m.Daemon.Alive()) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)) {
			t.FailNow()
		}

		n, err = unix.Pread(fd, buf, 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(want, buf[:n]))
		open = false
		assert.NoError(t, unix.Close(fd))

		if !ownsMount {
			assert.True(t, m.Daemon.Alive())
		}

		m.Daemon.Signal(unix.SIGTERM)

		if !assert.True(t, m.Daemon.WaitExit(exitTimeout)) {
			t.FailNow()
		}

		assert.Zero(t, m.Daemon.ExitCode())
	})

	t.Run("LazyUnmountWithClosedFDMmap", func(t *testing.T) {
		t.Parallel()
		m := &mounted{Mounted: mount.Mount(t, a, img, mount.Options{}), adapter: a}
		rel := "files/large_256k"
		want := m.wantBytes(t, rel)
		fd, err := unix.Open(m.Path(rel), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		open := true

		t.Cleanup(func() {
			if open {
				assert.NoError(t, unix.Close(fd))
			}
		})

		data, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ, unix.MAP_PRIVATE)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		mapped := true

		t.Cleanup(func() {
			if mapped {
				assert.NoError(t, unix.Munmap(data))
			}
		})

		if !assert.NoError(t, unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)) {
			t.FailNow()
		}

		open = false

		if !assert.NoError(t, unix.Close(fd)) {
			t.FailNow()
		}
		if !assert.ErrorIs(t, unix.Unmount(m.Root, 0), unix.EBUSY) {
			t.FailNow()
		}
		if !assert.True(t, mount.IsMountpoint(m.Root)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Unmount(m.Root, unix.MNT_DETACH)) {
			t.FailNow()
		}
		if !assert.False(t, mount.IsMountpoint(m.Root)) {
			t.FailNow()
		}

		select {
		case <-m.Daemon.Exited():
			t.Fatal("the daemon exited while a mapping still referenced the detached mount")

		case <-time.After(time.Second):
		}

		if !assert.True(t, bytes.Equal(want, data)) {
			t.FailNow()
		}
		if !assert.True(t, m.Daemon.Alive()) {
			t.FailNow()
		}

		assert.NoError(t, unix.Munmap(data))
		mapped = false

		m.Daemon.Signal(unix.SIGTERM)

		if !assert.True(t, m.Daemon.WaitExit(exitTimeout)) {
			t.FailNow()
		}

		assert.Zero(t, m.Daemon.ExitCode())
	})
}

func inodeMap(t *testing.T, root string) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	if !assert.NoError(t, filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
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
	})) {
		t.FailNow()
	}

	return out
}
