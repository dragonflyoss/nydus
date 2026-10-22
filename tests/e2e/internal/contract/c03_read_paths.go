package contract

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C03: reads that do not start or end where a sequential reader would:
// unaligned and boundary-straddling preads, vectored reads, reads at and
// past EOF, and holes.
func init() {
	Register(Case{ID: "C03", Name: "ReadPaths", Scope: Semantic, Run: runReadPaths})
}

func runReadPaths(t *testing.T, f *Fixture) {
	t.Run("ReadPastEOF", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, f.At("files/tiny_2b"))
		buf := make([]byte, 16)
		for _, off := range []int64{2, 1 << 20, 1 << 40} {
			n, err := unix.Pread(fd, buf, off)
			require.NoError(t, err, "pread at %d", off)
			require.Zero(t, n, "pread at %d is past EOF", off)
		}
		// A read straddling EOF is short, not padded.
		n, err := unix.Pread(fd, buf, 1)
		require.NoError(t, err)
		require.Equal(t, "i", string(buf[:n]))
	})

	t.Run("EmptyFile", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile(f.At("files/empty"))
		require.NoError(t, err)
		require.Empty(t, data)
	})

	t.Run("SparseHoleReadsZero", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/sparse_hole", "files/all_zeros", "sparse/all_hole", "sparse/islands_00"} {
			got, err := os.ReadFile(f.At(rel))
			require.NoError(t, err)
			require.True(t, bytes.Equal(wantBytes(t, f, rel), got), "%s: content differs", rel)
		}
	})

	t.Run("UnalignedCrossBoundary", func(t *testing.T) {
		t.Parallel()
		// Straddle every 4KiB block boundary with lengths that are not powers
		// of two, which is where chunk stitching tends to go wrong.
		rel := "files/ten_blocks"
		want := wantBytes(t, f, rel)
		fd := openRO(t, f.At(rel))
		for _, off := range []int64{0, 1, 4095, 4096, 4097, 8191, 8192, 12287, 20479, 40959} {
			for _, length := range []int{1, 3, 4095, 4096, 4097, 8193} {
				_ = unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)
				end := min(off+int64(length), int64(len(want)))
				buf := make([]byte, length)
				n, err := unix.Pread(fd, buf, off)
				require.NoError(t, err, "pread(off=%d len=%d)", off, length)
				require.Equal(t, int(end-off), n, "pread(off=%d len=%d) short read", off, length)
				require.True(t, bytes.Equal(want[off:end], buf[:n]),
					"pread(off=%d len=%d) returned different bytes", off, length)
			}
		}
	})

	t.Run("Preadv", func(t *testing.T) {
		t.Parallel()
		rel := "files/two_blocks"
		want := wantBytes(t, f, rel)
		fd := openRO(t, f.At(rel))

		first, second := make([]byte, 100), make([]byte, 4000)
		n, err := unix.Preadv(fd, [][]byte{first, second}, 4090)
		require.NoError(t, err)
		require.Equal(t, len(first)+len(second), n)
		require.True(t, bytes.Equal(want[4090:4190], first))
		require.True(t, bytes.Equal(want[4190:8190], second))

		// Vectors running past EOF are filled up to it and no further.
		third := make([]byte, 4096)
		n, err = unix.Preadv(fd, [][]byte{first, third}, 8000)
		require.NoError(t, err)
		require.Equal(t, len(want)-8000, n)
		require.True(t, bytes.Equal(want[8000:8100], first))
		require.True(t, bytes.Equal(want[8100:], third[:n-100]))
	})
}

// openRO opens path read-only for the rest of the test.
func openRO(t *testing.T, path string) int {
	t.Helper()
	// O_CLOEXEC: a daemon another parallel test starts must not inherit the
	// descriptor and keep this mount busy.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, err, "open %s", path)
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// withFile runs fn with path open read-only and closes it again, for loops
// over many files.
func withFile(t *testing.T, path string, fn func(fd int)) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, err, "open %s", path)
	defer func() { _ = unix.Close(fd) }()
	fn(fd)
}

// wantBytes returns the content rel has in the semantic image's source.
func wantBytes(t *testing.T, f *Fixture, rel string) []byte {
	t.Helper()
	src := f.Src(rel)
	require.NotEmpty(t, src, "%s: the image has no source tree", rel)
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	return data
}
