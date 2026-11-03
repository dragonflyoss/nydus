package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testSparse(t *testing.T, m *mounted) {
	var files, empty, huge []fstest.Entry

	for _, e := range m.Image.Want {
		switch {
		case e.Type != fstest.TypeReg:

		case e.Size == 0:
			empty = append(empty, e)

		default:
			files = append(files, e)

			if e.Size > 1<<32 {
				huge = append(huge, e)
			}
		}
	}

	if !assert.NotEmpty(t, files) {
		t.FailNow()
	}

	t.Run("MapIsWellFormed", func(t *testing.T) {
		t.Parallel()
		for _, e := range files {
			withFile(t, m.Path(string(e.Path)), func(fd int) { walkMap(t, fd, e) })
		}
	})

	t.Run("HolesReadZero", func(t *testing.T) {
		t.Parallel()
		for _, e := range files {
			withFile(t, m.Path(string(e.Path)), func(fd int) { readHoles(t, fd, e) })
		}
	})

	t.Run("DataIsNeverAHole", func(t *testing.T) {
		t.Parallel()
		for _, e := range files {
			if len(e.Extents) == 0 {
				continue
			}

			withFile(t, m.Path(string(e.Path)), func(fd int) {
				for _, x := range e.Extents {
					data, err := unix.Seek(fd, x.Offset, unix.SEEK_DATA)
					if !assert.NoError(t, err) {
						t.FailNow()
					}
					if !assert.Equal(t, x.Offset, data) {
						t.FailNow()
					}

					hole, err := unix.Seek(fd, x.Offset, unix.SEEK_HOLE)
					if !assert.NoError(t, err) {
						t.FailNow()
					}

					assert.GreaterOrEqual(t, hole, x.Offset+x.Length)
				}
			})
		}
	})

	t.Run("SetCurEnd", func(t *testing.T) {
		t.Parallel()
		e := files[len(files)/2]
		fd := openRO(t, m.Path(string(e.Path)))
		pos, err := unix.Seek(fd, 0, unix.SEEK_END)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, e.Size, pos) {
			t.FailNow()
		}

		pos, err = unix.Seek(fd, -e.Size/2, unix.SEEK_CUR)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, e.Size-e.Size/2, pos) {
			t.FailNow()
		}

		pos, err = unix.Seek(fd, e.Size/3, unix.SEEK_SET)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, e.Size/3, pos) {
			t.FailNow()
		}

		pos, err = unix.Seek(fd, e.Size+4096, unix.SEEK_SET)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, e.Size+4096, pos)
		n, err := unix.Read(fd, make([]byte, 16))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Zero(t, n)

		_, err = unix.Seek(fd, -1, unix.SEEK_SET)
		assert.ErrorIs(t, err, unix.EINVAL)
	})

	t.Run("DataHoleAtEOF", func(t *testing.T) {
		t.Parallel()
		for _, e := range []fstest.Entry{files[0], files[len(files)-1]} {
			fd := openRO(t, m.Path(string(e.Path)))
			pos, err := unix.Seek(fd, e.Size-1, unix.SEEK_HOLE)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, e.Size, pos) {
				t.FailNow()
			}

			for _, off := range []int64{e.Size, e.Size + 1} {
				_, err = unix.Seek(fd, off, unix.SEEK_DATA)
				if !assert.ErrorIs(t, err, unix.ENXIO) {
					t.FailNow()
				}

				_, err = unix.Seek(fd, off, unix.SEEK_HOLE)
				assert.ErrorIs(t, err, unix.ENXIO)
			}
		}
	})

	if m.Image.Corpus != fixture.Huge {
		t.Run("EmptyFileHasNoData", func(t *testing.T) {
			t.Parallel()
			if !assert.NotEmpty(t, empty) {
				t.FailNow()
			}

			fd := openRO(t, m.Path(string(empty[0].Path)))
			_, err := unix.Seek(fd, 0, unix.SEEK_DATA)
			if !assert.ErrorIs(t, err, unix.ENXIO) {
				t.FailNow()
			}

			_, err = unix.Seek(fd, 0, unix.SEEK_HOLE)
			assert.ErrorIs(t, err, unix.ENXIO)
		})

		return
	}

	t.Run("Beyond4GiB", func(t *testing.T) {
		t.Parallel()
		if !assert.NotEmpty(t, huge) {
			t.FailNow()
		}

		for _, e := range huge {
			withFile(t, m.Path(string(e.Path)), func(fd int) { readBeyond4GiB(t, fd, e) })
		}
	})
}

func walkMap(t *testing.T, fd int, e fstest.Entry) {
	t.Helper()
	for pos, steps := int64(0), 0; pos < e.Size; steps++ {
		if !assert.Less(t, steps, 1<<16) {
			t.FailNow()
		}

		data, err := unix.Seek(fd, pos, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			return
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.GreaterOrEqual(t, data, pos) {
			t.FailNow()
		}
		if !assert.Less(t, data, e.Size) {
			t.FailNow()
		}

		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Greater(t, hole, data) {
			t.FailNow()
		}
		if !assert.LessOrEqual(t, hole, e.Size) {
			t.FailNow()
		}

		pos = hole
	}
}

func readHoles(t *testing.T, fd int, e fstest.Entry) {
	t.Helper()
	for pos := int64(0); pos < e.Size; {
		hole, err := unix.Seek(fd, pos, unix.SEEK_HOLE)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if hole >= e.Size {
			return
		}

		next, err := unix.Seek(fd, hole, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			next = e.Size
		} else if !assert.NoError(t, err) {
			t.FailNow()
		}

		n := min(next-hole, 1<<20)
		buf := make([]byte, n)
		got, err := unix.Pread(fd, buf, hole)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.EqualValues(t, n, got) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(make([]byte, n), buf))
		pos = next
	}
}

func readBeyond4GiB(t *testing.T, fd int, e fstest.Entry) {
	t.Helper()
	pos, err := unix.Seek(fd, 0, unix.SEEK_END)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, e.Size, pos) {
		t.FailNow()
	}

	buf := make([]byte, 2)
	n, err := unix.Pread(fd, buf, e.Size-1)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, 1, n) {
		t.FailNow()
	}

	n, err = unix.Pread(fd, buf, e.Size)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Zero(t, n) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, e.Extents) {
		t.FailNow()
	}

	x := e.Extents[len(e.Extents)-1]
	pos, err = unix.Seek(fd, x.Offset, unix.SEEK_SET)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, x.Offset, pos) {
		t.FailNow()
	}

	data := make([]byte, x.Length)
	n, err = unix.Read(fd, data)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.EqualValues(t, x.Length, n) {
		t.FailNow()
	}

	sum := sha256.Sum256(data)
	assert.Equal(t, x.SHA256, hex.EncodeToString(sum[:]))
}

func withFile(t *testing.T, path string, fn func(fd int)) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = unix.Close(fd) }()
	fn(fd)
}
