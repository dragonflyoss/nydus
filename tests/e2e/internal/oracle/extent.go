package oracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Extent is a data range of a large sparse file; everything outside the
// extents of a file reads as zeros.
type Extent struct {
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

// DataExtents maps the data of a sparse source file: its non-zero 4KiB
// blocks, located with SEEK_DATA/SEEK_HOLE, coalesced into extents and
// hashed. It only reads the allocated parts of path, so it is cheap on the
// multi-gigabyte sparse files the corpora carry.
func DataExtents(t env.TB, path string) []Extent {
	t.Helper()
	const block = 4096
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	require.NoError(t, err)
	size := st.Size()

	var extents []Extent
	buf := make([]byte, block)
	zero := make([]byte, block)
	for off := int64(0); off < size; {
		data, err := unix.Seek(int(f.Fd()), off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		require.NoError(t, err, "SEEK_DATA %s at %d", path, off)
		hole, err := unix.Seek(int(f.Fd()), data, unix.SEEK_HOLE)
		require.NoError(t, err, "SEEK_HOLE %s at %d", path, data)
		for pos := data &^ (block - 1); pos < hole; pos += block {
			n := min(int64(block), size-pos)
			_, err := f.ReadAt(buf[:n], pos)
			require.NoError(t, err)
			if bytes.Equal(buf[:n], zero[:n]) {
				continue
			}
			if last := len(extents) - 1; last >= 0 && extents[last].Offset+extents[last].Length == pos {
				extents[last].Length += n
			} else {
				extents = append(extents, Extent{Offset: pos, Length: n})
			}
		}
		off = hole
	}

	for i := range extents {
		data := make([]byte, extents[i].Length)
		_, err := f.ReadAt(data, extents[i].Offset)
		require.NoError(t, err)
		sum := sha256.Sum256(data)
		extents[i].SHA256 = hex.EncodeToString(sum[:])
	}
	return extents
}

// VerifyExtents asserts that path is size bytes long, that every extent
// hashes as recorded, and that the start, middle and end of every gap
// between extents read as zeros. It never streams the holes in full.
func VerifyExtents(t env.TB, path string, size int64, extents []Extent) {
	t.Helper()
	const probe = 64 << 10
	f, err := os.Open(path)
	require.NoError(t, err, "open %s", path)
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	require.NoError(t, err)
	require.Equal(t, size, st.Size(), "%s: size", path)

	readAt := func(off, n int64) []byte {
		buf := make([]byte, n)
		_, err := f.ReadAt(buf, off)
		require.NoError(t, err, "%s: read %d bytes at %d", path, n, off)
		return buf
	}
	zero := make([]byte, probe)
	gap := func(start, end int64) {
		for _, off := range []int64{start, start + (end-start)/2, end - probe} {
			off = max(start, off)
			if n := min(int64(probe), end-off); n > 0 {
				require.True(t, bytes.Equal(zero[:n], readAt(off, n)), "%s: hole at %d is not zeros", path, off)
			}
		}
	}

	pos := int64(0)
	for _, e := range extents {
		gap(pos, e.Offset)
		sum := sha256.Sum256(readAt(e.Offset, e.Length))
		require.Equal(t, e.SHA256, hex.EncodeToString(sum[:]), "%s: data at %d", path, e.Offset)
		pos = e.Offset + e.Length
	}
	gap(pos, size)
}

// CompareExtents asserts that mnt holds the same bytes as the sparse source
// file src, reading only src's data and samples of its holes. A file with no
// data at all is sampled as one hole.
func CompareExtents(t env.TB, src, mnt string) {
	t.Helper()
	st, err := os.Stat(src)
	require.NoError(t, err)
	VerifyExtents(t, mnt, st.Size(), DataExtents(t, src))
}
