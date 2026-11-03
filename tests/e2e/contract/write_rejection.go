package contract

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func runWriteRejection(t *testing.T, f *Fixture) {
	file := f.Path("files/small_100b")
	dir := f.Path("dirs/empty_dir")
	link := f.Path("symlinks/link_to_file")

	fresh := f.Path("dirs/empty_dir/created")
	for name, op := range map[string]func() error{
		"OpenWriteOnly": func() error { return openErr(file, unix.O_WRONLY, 0) },
		"OpenReadWrite": func() error { return openErr(file, unix.O_RDWR, 0) },
		"OpenAppend":    func() error { return openErr(file, unix.O_WRONLY|unix.O_APPEND, 0) },
		"OpenTruncate":  func() error { return openErr(file, unix.O_RDONLY|unix.O_TRUNC, 0) },
		"OpenCreate":    func() error { return openErr(fresh, unix.O_CREAT|unix.O_WRONLY, 0o600) },
		// The read-only check precedes the ->tmpfile lookup, so even a
		// filesystem without O_TMPFILE support must answer EROFS.
		"OpenTmpfile": func() error { return openErr(f.Path("dirs"), unix.O_TMPFILE|unix.O_RDWR, 0o600) },
		"Truncate":    func() error { return unix.Truncate(file, 0) },
		"Unlink":      func() error { return unix.Unlink(file) },
		"Rmdir":       func() error { return unix.Rmdir(dir) },
		"Rename":      func() error { return unix.Rename(file, fresh) },
		"Link":        func() error { return unix.Link(file, fresh) },
		"Symlink":     func() error { return unix.Symlink("target", fresh) },
		"Mkdir":       func() error { return unix.Mkdir(fresh, 0o755) },
		"Mknod":       func() error { return unix.Mknod(fresh, unix.S_IFIFO|0o644, 0) },
		"Chmod":       func() error { return unix.Chmod(file, 0o600) },
		"Chown":       func() error { return unix.Chown(file, 12345, 12345) },
		"Lchown":      func() error { return unix.Lchown(link, 12345, 12345) },
		"UtimesNano": func() error {
			return unix.UtimesNano(file, []unix.Timespec{{Sec: 1}, {Sec: 1}})
		},
		"Setxattr":    func() error { return unix.Setxattr(file, "user.injected", []byte("x"), 0) },
		"Removexattr": func() error { return unix.Removexattr(f.Path("xattrs/user_basic"), "user.test") },
		"AccessWrite": func() error { return unix.Access(f.Path("perms/rwx"), unix.W_OK) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.ErrorIs(t, op(), unix.EROFS)
		})
	}

	t.Run("Fallocate", func(t *testing.T) {
		t.Parallel()
		// A writable descriptor cannot be had (see Open*), and the VFS checks
		// FMODE_WRITE before the read-only mount, so fallocate on a read-only
		// descriptor must fail with exactly EBADF without reaching the
		// filesystem; asserting just "some error" would also pass for an
		// implementation that allocated and then reported a failure.
		want := f.wantBytes(t, "files/small_100b")
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
