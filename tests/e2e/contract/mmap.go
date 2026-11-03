package contract

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func runMmap(t *testing.T, f *Fixture) {
	t.Run("SharedReadMatchesFile", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/ten_blocks", "files/sparse_hole", "files/large_256k"} {
			want := f.wantBytes(t, rel)
			data := mapFile(t, f.Path(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
			assert.True(t, bytes.Equal(want, data))
		}
	})

	t.Run("OffsetMapping", func(t *testing.T) {
		t.Parallel()
		// A mapping that starts mid-file faults its pages in out of order.
		rel := "files/large_256k"
		want := f.wantBytes(t, rel)
		page := os.Getpagesize()
		size := len(want) / page * page
		if !assert.Greater(t, size, page) {
			t.FailNow()
		}

		fd := openRO(t, f.Path(rel))
		data, err := unix.Mmap(fd, int64(page), size-page, unix.PROT_READ, unix.MAP_SHARED)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		defer func() { _ = unix.Munmap(data) }()

		for i := len(data) - page; i >= 0; i -= page {
			assert.True(t, bytes.Equal(want[page+i:page+i+page], data[i:i+page]))
		}
	})

	t.Run("TailPageIsZeroPadded", func(t *testing.T) {
		t.Parallel()
		// The bytes between EOF and the end of the last page read as zero.
		rel := "files/one_over_block"
		want := f.wantBytes(t, rel)
		page := os.Getpagesize()
		mapped := (len(want) + page - 1) / page * page
		data := mapFile(t, f.Path(rel), mapped, unix.PROT_READ, unix.MAP_PRIVATE)
		if !assert.True(t, bytes.Equal(want, data[:len(want)])) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(make([]byte, mapped-len(want)), data[len(want):]))
	})

	t.Run("PrivateWriteIsCopyOnWrite", func(t *testing.T) {
		t.Parallel()
		rel := "files/exact_block"
		want := f.wantBytes(t, rel)
		fd := openRO(t, f.Path(rel))
		data, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		data[0] ^= 0xff
		if !assert.NotEqual(t, want[0], data[0]) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Munmap(data)) {
			t.FailNow()
		}

		// Neither a fresh read nor a fresh mapping sees the private change.
		after, err := os.ReadFile(f.Path(rel))
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.True(t, bytes.Equal(want, after)) {
			t.FailNow()
		}

		again := mapFile(t, f.Path(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
		assert.True(t, bytes.Equal(want, again))
	})

	t.Run("SharedWriteMappingRejected", func(t *testing.T) {
		t.Parallel()
		// A shared writable mapping needs a writable descriptor, which the
		// mount refuses (WriteRejection); one over a read-only descriptor is EACCES.
		fd := openRO(t, f.Path("files/exact_block"))
		_, err := unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		assert.ErrorIs(t, err, unix.EACCES)
	})
}
