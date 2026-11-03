package contract

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func runZeroCopy(t *testing.T, f *Fixture) {
	rel := "files/ten_blocks"

	t.Run("Sendfile", func(t *testing.T) {
		t.Parallel()
		want := f.wantBytes(t, rel)
		src := openRO(t, f.Path(rel))
		dst, err := os.Create(filepath.Join(t.TempDir(), "sendfile"))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		defer func() { _ = dst.Close() }()
		// From an unaligned offset, through EOF.
		offset := int64(4095)
		var sent int

		for {
			n, err := unix.Sendfile(int(dst.Fd()), src, &offset, 1<<20)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if n == 0 {
				break
			}

			sent += n
		}

		if !assert.Equal(t, len(want)-4095, sent) {
			t.FailNow()
		}
		if !assert.EqualValues(t, len(want), offset) {
			t.FailNow()
		}

		got, err := os.ReadFile(dst.Name())
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(want[4095:], got))
	})

	t.Run("Splice", func(t *testing.T) {
		t.Parallel()
		want := f.wantBytes(t, rel)
		src := openRO(t, f.Path(rel))
		var p [2]int
		if !assert.NoError(t, unix.Pipe2(p[:], unix.O_CLOEXEC)) {
			t.FailNow()
		}

		defer func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) }()
		// A pipe holds 64KiB by default, more than the file.
		offset := int64(1)
		var got []byte
		buf := make([]byte, 64<<10)

		for offset < int64(len(want)) {
			n, err := unix.Splice(src, &offset, p[1], nil, 4097, 0)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Positive(t, int(n)) {
				t.FailNow()
			}

			for read := 0; read < int(n); {
				m, err := unix.Read(p[0], buf[:int(n)-read])
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				got = append(got, buf[:m]...)
				read += m
			}
		}

		assert.True(t, bytes.Equal(want[1:], got))
	})

	t.Run("CopyFileRange", func(t *testing.T) {
		t.Parallel()
		want := f.wantBytes(t, rel)
		src := openRO(t, f.Path(rel))
		dstPath := filepath.Join(t.TempDir(), "copy")
		dst, err := unix.Open(dstPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		defer func() { _ = unix.Close(dst) }()

		n, err := unix.CopyFileRange(src, nil, dst, nil, len(want), 0)
		if errors.Is(err, unix.EXDEV) {
			// The destination has to be writable, so it is always on another
			// filesystem, and the kernel refuses most cross-filesystem copies
			// before the source is involved; callers then fall back to
			// read/write, which the other cases cover.
			t.Logf("copy_file_range across filesystems: %v", err)
			return
		}

		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, len(want), n) {
			t.FailNow()
		}

		got, err := os.ReadFile(dstPath)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(want, got))
	})

	if f.directIO(f.Path(rel)) {
		t.Run("DirectIO", func(t *testing.T) {
			t.Parallel()
			want := f.wantBytes(t, rel)
			fd := openDirect(t, f.Path(rel))
			buf := alignedBuffer(t, len(want)+4096)
			// Aligned blocks, then a read running into EOF, which O_DIRECT
			// shortens like any other read.
			for _, off := range []int{0, 4096, 8192 * 2} {
				n, err := unix.Pread(fd, buf[:8192], int64(off))
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				if !assert.Equal(t, 8192, n) {
					t.FailNow()
				}

				assert.True(t, bytes.Equal(want[off:off+8192], buf[:n]))
			}

			n, err := unix.Pread(fd, buf[:3*4096], int64(len(want)-4096))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, 4096, n) {
				t.FailNow()
			}

			assert.True(t, bytes.Equal(want[len(want)-4096:], buf[:n]))
		})
	}

	t.Run("OpenFlags", func(t *testing.T) {
		t.Parallel()
		if !assert.ErrorIs(t, openErr(f.Path("files/tiny_2b"), unix.O_RDONLY|unix.O_DIRECTORY, 0), unix.ENOTDIR) {
			t.FailNow()
		}
		if !assert.NoError(t, openErr(f.Path("dirs"), unix.O_RDONLY|unix.O_DIRECTORY, 0)) {
			t.FailNow()
		}
		if !assert.ErrorIs(t, openErr(f.Path("dirs"), unix.O_WRONLY, 0), unix.EISDIR) {
			t.FailNow()
		}

		// O_PATH resolves a FIFO without engaging pipe semantics (a plain
		// open for reading would block) and still allows fstat.
		fd, err := unix.Open(f.Path("special/fifo"), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		var st unix.Stat_t
		if !assert.NoError(t, unix.Fstat(fd, &st)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Close(fd)) {
			t.FailNow()
		}
		if !assert.EqualValues(t, unix.S_IFIFO, st.Mode&unix.S_IFMT) {
			t.FailNow()
		}

		// O_PATH|O_NOFOLLOW on a symlink yields the link itself.
		fd, err = unix.Open(f.Path("symlinks/link_to_file"), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Fstat(fd, &st)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Close(fd)) {
			t.FailNow()
		}

		assert.EqualValues(t, unix.S_IFLNK, st.Mode&unix.S_IFMT)
	})

	t.Run("OpenatRelative", func(t *testing.T) {
		t.Parallel()
		dirFd := openDir(t, f.Path("files"))
		fd, err := unix.Openat(dirFd, "tiny_2b", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		defer func() { _ = unix.Close(fd) }()
		buf := make([]byte, 16)
		n, err := unix.Read(fd, buf)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, "hi", string(buf[:n]))

		var stx unix.Statx_t
		if !assert.NoError(t, unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx)) {
			t.FailNow()
		}

		assert.EqualValues(t, 2, stx.Size)
	})
}

// alignedBuffer returns a page-aligned buffer for the rest of the test,
// which O_DIRECT requires.
func alignedBuffer(t *testing.T, size int) []byte {
	t.Helper()
	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Munmap(buf) })

	return buf
}
