package fstest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Extent is a data range of a large sparse file; everything outside the
// extents of a file reads as zeros.
type Extent struct {
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

// dataExtents maps the data of a sparse source file: its non-zero 4KiB
// blocks, located with SEEK_DATA/SEEK_HOLE, coalesced into extents and
// hashed. It only reads the allocated parts of path, so it is cheap on the
// multi-gigabyte sparse files the corpora carry.
func dataExtents(t testing.TB, path string) []Extent {
	t.Helper()
	const block = 4096
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	size := st.Size()

	ranges, err := DataRanges(f)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var extents []Extent
	buf := make([]byte, block)
	zero := make([]byte, block)

	for _, r := range ranges {
		for pos := r[0] &^ (block - 1); pos < r[1]; pos += block {
			n := min(int64(block), size-pos)
			if _, err := f.ReadAt(buf[:n], pos); !assert.NoError(t, err) {
				t.FailNow()
			}
			if bytes.Equal(buf[:n], zero[:n]) {
				continue
			}

			if last := len(extents) - 1; last >= 0 && extents[last].Offset+extents[last].Length == pos {
				extents[last].Length += n
			} else {
				extents = append(extents, Extent{Offset: pos, Length: n})
			}
		}
	}

	for i := range extents {
		data := make([]byte, extents[i].Length)
		if _, err := f.ReadAt(data, extents[i].Offset); !assert.NoError(t, err) {
			t.FailNow()
		}

		sum := sha256.Sum256(data)
		extents[i].SHA256 = hex.EncodeToString(sum[:])
	}

	return extents
}

// DataRanges returns the [start, end) ranges of f that SEEK_DATA and
// SEEK_HOLE report as data, so a reader can skip the holes of a large
// sparse file.
func DataRanges(f *os.File) ([][2]int64, error) {
	var ranges [][2]int64
	fd := int(f.Fd())

	for off := int64(0); ; {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			return ranges, nil
		}
		if err != nil {
			return nil, fmt.Errorf("SEEK_DATA %s: %w", f.Name(), err)
		}

		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil {
			return nil, fmt.Errorf("SEEK_HOLE %s: %w", f.Name(), err)
		}

		ranges = append(ranges, [2]int64{data, hole})
		off = hole
	}
}

// VerifyExtents asserts that path is size bytes long, that every extent
// hashes as recorded, and that the start, middle and end of every gap
// between extents read as zeros. It never streams the holes in full.
func VerifyExtents(t testing.TB, path string, size int64, extents []Extent) {
	t.Helper()
	const probe = 64 << 10
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, size, st.Size()) {
		t.FailNow()
	}

	readAt := func(off, n int64) []byte {
		buf := make([]byte, n)
		_, err := f.ReadAt(buf, off)
		assert.NoError(t, err)

		return buf
	}

	zero := make([]byte, probe)

	gap := func(start, end int64) {
		for _, off := range []int64{start, start + (end-start)/2, end - probe} {
			off = max(start, off)
			if n := min(int64(probe), end-off); n > 0 {
				assert.True(t, bytes.Equal(zero[:n], readAt(off, n)))
			}
		}
	}

	pos := int64(0)

	for _, e := range extents {
		gap(pos, e.Offset)
		sum := sha256.Sum256(readAt(e.Offset, e.Length))
		if !assert.Equal(t, e.SHA256, hex.EncodeToString(sum[:])) {
			t.FailNow()
		}

		pos = e.Offset + e.Length
	}

	gap(pos, size)
}

// compareExtents asserts that mnt holds the same bytes as the sparse source
// file src, reading only src's data and samples of its holes. A file with no
// data at all is sampled as one hole.
func compareExtents(t testing.TB, src, mnt string) {
	t.Helper()
	st, err := os.Stat(src)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	VerifyExtents(t, mnt, st.Size(), dataExtents(t, src))
}
