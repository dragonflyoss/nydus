package contract

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C09: memory mappings of files on the mount: shared and private reads, the
// zero-filled tail page, private copy-on-write, and no shared writable
// mapping.
func init() {
	Register(Case{ID: "C09", Name: "Mmap", Scope: Semantic, Run: runMmap})
}

func runMmap(t *testing.T, f *Fixture) {
	t.Run("SharedReadMatchesFile", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/ten_blocks", "files/sparse_hole", "files/large_256k"} {
			want := wantBytes(t, f, rel)
			data := mapFile(t, f.At(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
			require.True(t, bytes.Equal(want, data), "%s: mapped content differs", rel)
		}
	})

	t.Run("OffsetMapping", func(t *testing.T) {
		t.Parallel()
		// A mapping that starts mid-file faults its pages in out of order.
		rel := "files/large_256k"
		want := wantBytes(t, f, rel)
		page := os.Getpagesize()
		fd := openRO(t, f.At(rel))
		data, err := unix.Mmap(fd, int64(3*page), 5*page, unix.PROT_READ, unix.MAP_SHARED)
		require.NoError(t, err)
		defer func() { _ = unix.Munmap(data) }()
		for i := len(data) - page; i >= 0; i -= page {
			require.True(t, bytes.Equal(want[3*page+i:3*page+i+page], data[i:i+page]), "page %d of the mapping", i/page)
		}
	})

	t.Run("TailPageIsZeroPadded", func(t *testing.T) {
		t.Parallel()
		// The bytes between EOF and the end of the last page read as zero.
		rel := "files/one_over_block"
		want := wantBytes(t, f, rel)
		page := os.Getpagesize()
		mapped := (len(want) + page - 1) / page * page
		data := mapFile(t, f.At(rel), mapped, unix.PROT_READ, unix.MAP_PRIVATE)
		require.True(t, bytes.Equal(want, data[:len(want)]))
		require.Equal(t, make([]byte, mapped-len(want)), data[len(want):], "bytes past EOF are not zero")
	})

	t.Run("PrivateWriteIsCopyOnWrite", func(t *testing.T) {
		t.Parallel()
		rel := "files/exact_block"
		want := wantBytes(t, f, rel)
		fd := openRO(t, f.At(rel))
		data, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		require.NoError(t, err)
		data[0] ^= 0xff
		require.NotEqual(t, want[0], data[0], "a MAP_PRIVATE mapping should be writable")
		require.NoError(t, unix.Munmap(data))

		// Neither a fresh read nor a fresh mapping sees the private change.
		after, err := os.ReadFile(f.At(rel))
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, after), "a MAP_PRIVATE write leaked into the file")
		again := mapFile(t, f.At(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
		require.True(t, bytes.Equal(want, again), "a MAP_PRIVATE write leaked into the page cache")
	})

	t.Run("SharedWriteMappingRejected", func(t *testing.T) {
		t.Parallel()
		// A shared writable mapping needs a writable descriptor, which the
		// mount refuses (C08); one over a read-only descriptor is EACCES.
		fd := openRO(t, f.At("files/exact_block"))
		_, err := unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		require.ErrorIs(t, err, unix.EACCES)
	})
}

// mapFile maps length bytes of path for the rest of the test.
func mapFile(t *testing.T, path string, length, prot, flags int) []byte {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, err, "open %s", path)
	defer func() { _ = unix.Close(fd) }()
	data, err := unix.Mmap(fd, 0, length, prot, flags)
	require.NoError(t, err, "mmap %s", path)
	t.Cleanup(func() { _ = unix.Munmap(data) })
	return data
}
