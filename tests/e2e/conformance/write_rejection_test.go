package conformance

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testWriteRejection(t *testing.T, m *mounted) {
	file := m.Path("files/small_100b")
	dir := m.Path("dirs/empty_dir")
	link := m.Path("symlinks/link_to_file")

	fresh := m.Path("dirs/empty_dir/created")
	for name, op := range map[string]func() error{
		"OpenWriteOnly": func() error { return openErr(file, unix.O_WRONLY, 0) },
		"OpenReadWrite": func() error { return openErr(file, unix.O_RDWR, 0) },
		"OpenAppend":    func() error { return openErr(file, unix.O_WRONLY|unix.O_APPEND, 0) },
		"OpenTruncate":  func() error { return openErr(file, unix.O_RDONLY|unix.O_TRUNC, 0) },
		"OpenCreate":    func() error { return openErr(fresh, unix.O_CREAT|unix.O_WRONLY, 0o600) },
		"OpenTmpfile":   func() error { return openErr(m.Path("dirs"), unix.O_TMPFILE|unix.O_RDWR, 0o600) },
		"Truncate":      func() error { return unix.Truncate(file, 0) },
		"Unlink":        func() error { return unix.Unlink(file) },
		"Rmdir":         func() error { return unix.Rmdir(dir) },
		"Rename":        func() error { return unix.Rename(file, fresh) },
		"Link":          func() error { return unix.Link(file, fresh) },
		"Symlink":       func() error { return unix.Symlink("target", fresh) },
		"Mkdir":         func() error { return unix.Mkdir(fresh, 0o755) },
		"Mknod":         func() error { return unix.Mknod(fresh, unix.S_IFIFO|0o644, 0) },
		"Chmod":         func() error { return unix.Chmod(file, 0o600) },
		"Chown":         func() error { return unix.Chown(file, 12345, 12345) },
		"Lchown":        func() error { return unix.Lchown(link, 12345, 12345) },
		"UtimesNano": func() error {
			return unix.UtimesNano(file, []unix.Timespec{{Sec: 1}, {Sec: 1}})
		},
		"Setxattr":    func() error { return unix.Setxattr(file, "user.injected", []byte("x"), 0) },
		"Removexattr": func() error { return unix.Removexattr(m.Path("xattrs/user_basic"), "user.test") },
		"AccessWrite": func() error { return unix.Access(m.Path("perms/rwx"), unix.W_OK) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.ErrorIs(t, op(), unix.EROFS)
		})
	}

	t.Run("Fallocate", func(t *testing.T) {
		t.Parallel()
		want := m.wantBytes(t, "files/small_100b")
		fd := openRO(t, file)

		for _, mode := range []uint32{0, unix.FALLOC_FL_KEEP_SIZE, unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE} {
			assert.ErrorIs(t, unix.Fallocate(fd, mode, 0, 4096), unix.EBADF)
		}

		got, err := os.ReadFile(file)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(want, got))
	})

	t.Run("WriteOnReadOnlyDescriptor", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, file)
		_, err := unix.Write(fd, []byte("x"))
		if !assert.ErrorIs(t, err, unix.EBADF) {
			t.FailNow()
		}

		_, err = unix.Pwrite(fd, []byte("x"), 0)
		if !assert.ErrorIs(t, err, unix.EBADF) {
			t.FailNow()
		}

		assert.ErrorIs(t, unix.Ftruncate(fd, 0), unix.EINVAL)
	})

	t.Run("NothingChanged", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		assert.ErrorIs(t, unix.Lstat(fresh, &st), unix.ENOENT)
		entries, err := os.ReadDir(dir)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Empty(t, entries)
	})
}
