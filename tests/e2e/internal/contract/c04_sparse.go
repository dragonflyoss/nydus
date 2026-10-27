package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C04: lseek and the SEEK_DATA/SEEK_HOLE map obey POSIX, including offsets
// past 4GiB. No hole granularity is assumed: the FUSE reader has no lseek
// handler, so the kernel reports every file as one data extent, and a
// chunked image would not report the extents of the source anyway.
func init() {
	Register(Case{ID: "C04", Name: "Sparse", Scope: Semantic | Data, Run: runSparse})
}

func runSparse(t *testing.T, f *Fixture) {
	var files, empty, huge []oracle.Entry
	for _, e := range f.Image.Want {
		switch {
		case e.Type != "reg":
		case e.Size == 0:
			empty = append(empty, e)
		default:
			files = append(files, e)
			if e.Size > 1<<32 {
				huge = append(huge, e)
			}
		}
	}
	require.NotEmpty(t, files, "the image has no non-empty regular file")

	t.Run("MapIsWellFormed", func(t *testing.T) {
		t.Parallel()
		for _, e := range files {
			withFile(t, f.At(string(e.Path)), func(fd int) { walkMap(t, fd, e) })
		}
	})

	t.Run("HolesReadZero", func(t *testing.T) {
		t.Parallel()
		for _, e := range files {
			withFile(t, f.At(string(e.Path)), func(fd int) { readHoles(t, fd, e) })
		}
	})

	t.Run("DataIsNeverAHole", func(t *testing.T) {
		t.Parallel()
		// The recorded data extents of large sparse files must lie in what
		// the map reports as data, or a hole-aware copy would drop them.
		for _, e := range files {
			if len(e.Extents) == 0 {
				continue
			}
			withFile(t, f.At(string(e.Path)), func(fd int) {
				for _, x := range e.Extents {
					data, err := unix.Seek(fd, x.Offset, unix.SEEK_DATA)
					require.NoError(t, err, "%s: SEEK_DATA at %d", e.Path, x.Offset)
					require.Equal(t, x.Offset, data, "%s: data at %d is reported as a hole", e.Path, x.Offset)
					hole, err := unix.Seek(fd, x.Offset, unix.SEEK_HOLE)
					require.NoError(t, err)
					require.GreaterOrEqual(t, hole, x.Offset+x.Length, "%s: hole inside the data at %d", e.Path, x.Offset)
				}
			})
		}
	})

	t.Run("SetCurEnd", func(t *testing.T) {
		t.Parallel()
		e := files[len(files)/2]
		fd := openRO(t, f.At(string(e.Path)))
		pos, err := unix.Seek(fd, 0, unix.SEEK_END)
		require.NoError(t, err)
		require.Equal(t, e.Size, pos, "%s: SEEK_END", e.Path)
		pos, err = unix.Seek(fd, -e.Size/2, unix.SEEK_CUR)
		require.NoError(t, err)
		require.Equal(t, e.Size-e.Size/2, pos, "%s: SEEK_CUR", e.Path)
		pos, err = unix.Seek(fd, e.Size/3, unix.SEEK_SET)
		require.NoError(t, err)
		require.Equal(t, e.Size/3, pos, "%s: SEEK_SET", e.Path)

		// Seeking past EOF is allowed; reading there returns nothing.
		pos, err = unix.Seek(fd, e.Size+4096, unix.SEEK_SET)
		require.NoError(t, err)
		require.Equal(t, e.Size+4096, pos)
		n, err := unix.Read(fd, make([]byte, 16))
		require.NoError(t, err)
		require.Zero(t, n)

		_, err = unix.Seek(fd, -1, unix.SEEK_SET)
		require.ErrorIs(t, err, unix.EINVAL, "negative offset")
	})

	t.Run("DataHoleAtEOF", func(t *testing.T) {
		t.Parallel()
		for _, e := range []oracle.Entry{files[0], files[len(files)-1]} {
			fd := openRO(t, f.At(string(e.Path)))
			// SEEK_HOLE from the last byte always lands at EOF, and both whences
			// fail with ENXIO at or past it.
			pos, err := unix.Seek(fd, e.Size-1, unix.SEEK_HOLE)
			require.NoError(t, err)
			require.Equal(t, e.Size, pos, "%s: SEEK_HOLE from the last byte", e.Path)
			for _, off := range []int64{e.Size, e.Size + 1} {
				_, err = unix.Seek(fd, off, unix.SEEK_DATA)
				require.ErrorIs(t, err, unix.ENXIO, "%s: SEEK_DATA at %d", e.Path, off)
				_, err = unix.Seek(fd, off, unix.SEEK_HOLE)
				require.ErrorIs(t, err, unix.ENXIO, "%s: SEEK_HOLE at %d", e.Path, off)
			}
		}
	})

	t.Run("EmptyFileHasNoData", func(t *testing.T) {
		t.Parallel()
		if f.Image.Corpus == fixture.Huge {
			return
		}
		require.NotEmpty(t, empty, "the image has no empty regular file")
		fd := openRO(t, f.At(string(empty[0].Path)))
		_, err := unix.Seek(fd, 0, unix.SEEK_DATA)
		require.ErrorIs(t, err, unix.ENXIO)
		_, err = unix.Seek(fd, 0, unix.SEEK_HOLE)
		require.ErrorIs(t, err, unix.ENXIO)
	})

	t.Run("Beyond4GiB", func(t *testing.T) {
		t.Parallel()
		// Only the Huge corpus carries files past 4GiB, where sizes and
		// offsets need the extended inode.
		if f.Image.Corpus == fixture.Huge {
			require.NotEmpty(t, huge, "the image has no file past 4GiB")
		}
		for _, e := range huge {
			withFile(t, f.At(string(e.Path)), func(fd int) { readBeyond4GiB(t, fd, e) })
		}
	})
}

// walkMap alternates SEEK_DATA and SEEK_HOLE from 0: every step must
// advance, stay within the file, and terminate.
func walkMap(t *testing.T, fd int, e oracle.Entry) {
	t.Helper()
	for pos, steps := int64(0), 0; pos < e.Size; steps++ {
		require.Less(t, steps, 1<<16, "%s: extent walk did not terminate", e.Path)
		data, err := unix.Seek(fd, pos, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			return
		}
		require.NoError(t, err, "%s: SEEK_DATA at %d", e.Path, pos)
		require.GreaterOrEqual(t, data, pos, "%s: SEEK_DATA went backwards", e.Path)
		require.Less(t, data, e.Size, "%s: SEEK_DATA past EOF", e.Path)

		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		require.NoError(t, err, "%s: SEEK_HOLE at %d", e.Path, data)
		require.Greater(t, hole, data, "%s: SEEK_HOLE did not advance", e.Path)
		require.LessOrEqual(t, hole, e.Size, "%s: SEEK_HOLE past EOF", e.Path)
		pos = hole
	}
}

// readHoles reads (up to 1MiB of) every hole the map reports and requires
// zeros there.
func readHoles(t *testing.T, fd int, e oracle.Entry) {
	t.Helper()
	for pos := int64(0); pos < e.Size; {
		hole, err := unix.Seek(fd, pos, unix.SEEK_HOLE)
		require.NoError(t, err, "%s: SEEK_HOLE at %d", e.Path, pos)
		if hole >= e.Size {
			return
		}
		next, err := unix.Seek(fd, hole, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			next = e.Size
		} else {
			require.NoError(t, err, "%s: SEEK_DATA at %d", e.Path, hole)
		}
		n := min(next-hole, 1<<20)
		buf := make([]byte, n)
		_, err = unix.Pread(fd, buf, hole)
		require.NoError(t, err)
		require.Equal(t, make([]byte, n), buf,
			"%s: bytes %d..%d are reported as a hole but are not zero", e.Path, hole, hole+n)
		pos = next
	}
}

// readBeyond4GiB checks EOF and the last data extent of a file past 4GiB.
func readBeyond4GiB(t *testing.T, fd int, e oracle.Entry) {
	t.Helper()
	pos, err := unix.Seek(fd, 0, unix.SEEK_END)
	require.NoError(t, err)
	require.Equal(t, e.Size, pos, "%s: SEEK_END", e.Path)

	buf := make([]byte, 2)
	n, err := unix.Pread(fd, buf, e.Size-1)
	require.NoError(t, err)
	require.Equal(t, 1, n, "%s: read across EOF", e.Path)
	n, err = unix.Pread(fd, buf, e.Size)
	require.NoError(t, err)
	require.Zero(t, n, "%s: read at EOF", e.Path)

	require.NotEmpty(t, e.Extents, "%s: no recorded data", e.Path)
	x := e.Extents[len(e.Extents)-1]
	pos, err = unix.Seek(fd, x.Offset, unix.SEEK_SET)
	require.NoError(t, err)
	require.Equal(t, x.Offset, pos)
	data := make([]byte, x.Length)
	n, err = unix.Read(fd, data)
	require.NoError(t, err)
	require.EqualValues(t, x.Length, n, "%s: short read at %d", e.Path, x.Offset)
	sum := sha256.Sum256(data)
	require.Equal(t, x.SHA256, hex.EncodeToString(sum[:]), "%s: data at %d", e.Path, x.Offset)
}
