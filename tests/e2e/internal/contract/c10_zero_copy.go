package contract

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C10: the read paths that bypass read(2): sendfile, splice,
// copy_file_range and O_DIRECT, plus the open flags that change what an open
// returns.
func init() {
	Register(Case{ID: "C10", Name: "ZeroCopy", Scope: Semantic, Run: runZeroCopy})
}

func runZeroCopy(t *testing.T, f *Fixture) {
	rel := "files/ten_blocks"

	t.Run("Sendfile", func(t *testing.T) {
		t.Parallel()
		want := wantBytes(t, f, rel)
		src := openRO(t, f.At(rel))
		dst, err := os.Create(filepath.Join(t.TempDir(), "sendfile"))
		require.NoError(t, err)
		defer func() { _ = dst.Close() }()

		// From an unaligned offset, through EOF.
		offset := int64(4095)
		var sent int
		for {
			n, err := unix.Sendfile(int(dst.Fd()), src, &offset, 1<<20)
			require.NoError(t, err)
			if n == 0 {
				break
			}
			sent += n
		}
		require.Equal(t, len(want)-4095, sent)
		require.EqualValues(t, len(want), offset)
		got, err := os.ReadFile(dst.Name())
		require.NoError(t, err)
		require.True(t, bytes.Equal(want[4095:], got), "sendfile copied different bytes")
	})

	t.Run("Splice", func(t *testing.T) {
		t.Parallel()
		want := wantBytes(t, f, rel)
		src := openRO(t, f.At(rel))
		var p [2]int
		require.NoError(t, unix.Pipe2(p[:], unix.O_CLOEXEC))
		defer func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) }()

		// A pipe holds 64KiB by default, more than the file.
		offset := int64(1)
		var got []byte
		buf := make([]byte, 64<<10)
		for offset < int64(len(want)) {
			n, err := unix.Splice(src, &offset, p[1], nil, 4097, 0)
			require.NoError(t, err)
			require.Positive(t, int(n), "splice stopped at %d", offset)
			for read := 0; read < int(n); {
				m, err := unix.Read(p[0], buf[:int(n)-read])
				require.NoError(t, err)
				got = append(got, buf[:m]...)
				read += m
			}
		}
		require.True(t, bytes.Equal(want[1:], got), "splice moved different bytes")
	})

	t.Run("CopyFileRange", func(t *testing.T) {
		t.Parallel()
		want := wantBytes(t, f, rel)
		src := openRO(t, f.At(rel))
		dstPath := filepath.Join(t.TempDir(), "copy")
		dst, err := unix.Open(dstPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
		require.NoError(t, err)
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
		require.NoError(t, err)
		require.Equal(t, len(want), n)
		got, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, got), "copy_file_range copied different bytes")
	})

	t.Run("DirectIO", func(t *testing.T) {
		t.Parallel()
		want := wantBytes(t, f, rel)
		fd, ok := openDirect(t, f, f.At(rel))
		if !ok {
			return
		}
		buf := alignedBuffer(len(want) + 4096)
		// Aligned blocks, then a read running into EOF, which O_DIRECT
		// shortens like any other read.
		for _, off := range []int{0, 4096, 8192 * 2} {
			n, err := unix.Pread(fd, buf[:8192], int64(off))
			require.NoError(t, err, "O_DIRECT pread at %d", off)
			require.Equal(t, 8192, n)
			require.True(t, bytes.Equal(want[off:off+8192], buf[:n]), "O_DIRECT pread at %d", off)
		}
		n, err := unix.Pread(fd, buf[:3*4096], int64(len(want)-4096))
		require.NoError(t, err)
		require.Equal(t, 4096, n, "O_DIRECT read across EOF")
		require.True(t, bytes.Equal(want[len(want)-4096:], buf[:n]))
	})

	t.Run("OpenFlags", func(t *testing.T) {
		t.Parallel()
		openErr := func(path string, flags int) error {
			fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0)
			if err == nil {
				_ = unix.Close(fd)
			}
			return err
		}
		require.ErrorIs(t, openErr(f.At("files/tiny_2b"), unix.O_RDONLY|unix.O_DIRECTORY), unix.ENOTDIR)
		require.NoError(t, openErr(f.At("dirs"), unix.O_RDONLY|unix.O_DIRECTORY))
		require.ErrorIs(t, openErr(f.At("dirs"), unix.O_WRONLY), unix.EISDIR)

		// O_PATH resolves a FIFO without engaging pipe semantics (a plain
		// open for reading would block) and still allows fstat.
		fd, err := unix.Open(f.At("special/fifo"), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.NoError(t, err, "O_PATH must work on a FIFO")
		var st unix.Stat_t
		require.NoError(t, unix.Fstat(fd, &st))
		require.NoError(t, unix.Close(fd))
		require.EqualValues(t, unix.S_IFIFO, st.Mode&unix.S_IFMT)

		// O_PATH|O_NOFOLLOW on a symlink yields the link itself.
		fd, err = unix.Open(f.At("symlinks/link_to_file"), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		require.NoError(t, unix.Fstat(fd, &st))
		require.NoError(t, unix.Close(fd))
		require.EqualValues(t, unix.S_IFLNK, st.Mode&unix.S_IFMT)
	})

	t.Run("OpenatRelative", func(t *testing.T) {
		t.Parallel()
		dirFd := openDir(t, f.At("files"))
		fd, err := unix.Openat(dirFd, "tiny_2b", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()
		buf := make([]byte, 16)
		n, err := unix.Read(fd, buf)
		require.NoError(t, err)
		require.Equal(t, "hi", string(buf[:n]))

		var stx unix.Statx_t
		require.NoError(t, unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx))
		require.EqualValues(t, 2, stx.Size)
	})
}

// alignedBuffer returns a page-aligned slice, which O_DIRECT requires.
func alignedBuffer(size int) []byte {
	page := os.Getpagesize()
	raw := make([]byte, size+page)
	off := int(uintptr(unsafe.Pointer(&raw[0])) % uintptr(page))
	if off != 0 {
		off = page - off
	}
	return raw[off : off+size]
}
