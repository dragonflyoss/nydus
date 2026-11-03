package conformance

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testReadPaths(t *testing.T, m *mounted) {
	t.Run("ReadPastEOF", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, m.Path("files/tiny_2b"))
		buf := make([]byte, 16)

		for _, off := range []int64{2, 1 << 20, 1 << 40} {
			n, err := unix.Pread(fd, buf, off)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Zero(t, n)
		}

		n, err := unix.Pread(fd, buf, 1)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, "i", string(buf[:n]))
	})

	t.Run("EmptyFile", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile(m.Path("files/empty"))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Empty(t, data)
	})

	t.Run("SparseHoleReadsZero", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/sparse_hole", "files/all_zeros", "sparse/all_hole", "sparse/islands_00"} {
			got, err := os.ReadFile(m.Path(rel))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.True(t, bytes.Equal(m.wantBytes(t, rel), got))
		}
	})

	t.Run("UnalignedCrossBoundary", func(t *testing.T) {
		t.Parallel()
		rel := "files/ten_blocks"
		want := m.wantBytes(t, rel)
		fd := openRO(t, m.Path(rel))

		for _, off := range []int64{0, 1, 4095, 4096, 4097, 8191, 8192, 12287, 20479, 40959} {
			for _, length := range []int{1, 3, 4095, 4096, 4097, 8193} {
				_ = unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)
				end := min(off+int64(length), int64(len(want)))
				buf := make([]byte, length)
				n, err := unix.Pread(fd, buf, off)
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				if !assert.Equal(t, int(end-off), n) {
					t.FailNow()
				}

				assert.True(t, bytes.Equal(want[off:end], buf[:n]))
			}
		}
	})

	t.Run("Preadv", func(t *testing.T) {
		t.Parallel()
		rel := "files/two_blocks"
		want := m.wantBytes(t, rel)
		fd := openRO(t, m.Path(rel))

		first, second := make([]byte, 100), make([]byte, 4000)
		n, err := unix.Preadv(fd, [][]byte{first, second}, 4090)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, len(first)+len(second), n) {
			t.FailNow()
		}
		if !assert.True(t, bytes.Equal(want[4090:4190], first)) {
			t.FailNow()
		}
		if !assert.True(t, bytes.Equal(want[4190:8190], second)) {
			t.FailNow()
		}

		third := make([]byte, 4096)
		n, err = unix.Preadv(fd, [][]byte{first, third}, 8000)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, len(want)-8000, n) {
			t.FailNow()
		}
		if !assert.True(t, bytes.Equal(want[8000:8100], first)) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(want[8100:], third[:n-100]))
	})
}
