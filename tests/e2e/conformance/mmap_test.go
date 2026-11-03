package conformance

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testMmap(t *testing.T, m *mounted) {
	t.Run("SharedReadMatchesFile", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/ten_blocks", "files/sparse_hole", "files/large_256k"} {
			want := m.wantBytes(t, rel)
			data := mapFile(t, m.Path(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
			assert.True(t, bytes.Equal(want, data))
		}
	})

	t.Run("OffsetMapping", func(t *testing.T) {
		t.Parallel()
		rel := "files/large_256k"
		want := m.wantBytes(t, rel)
		page := os.Getpagesize()
		size := len(want) / page * page
		if !assert.Greater(t, size, page) {
			t.FailNow()
		}

		fd := openRO(t, m.Path(rel))
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
		rel := "files/one_over_block"
		want := m.wantBytes(t, rel)
		page := os.Getpagesize()
		mapped := (len(want) + page - 1) / page * page
		data := mapFile(t, m.Path(rel), mapped, unix.PROT_READ, unix.MAP_PRIVATE)
		if !assert.True(t, bytes.Equal(want, data[:len(want)])) {
			t.FailNow()
		}

		assert.True(t, bytes.Equal(make([]byte, mapped-len(want)), data[len(want):]))
	})

	t.Run("PrivateWriteIsCopyOnWrite", func(t *testing.T) {
		t.Parallel()
		rel := "files/exact_block"
		want := m.wantBytes(t, rel)
		fd := openRO(t, m.Path(rel))
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

		after, err := os.ReadFile(m.Path(rel))
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.True(t, bytes.Equal(want, after)) {
			t.FailNow()
		}

		again := mapFile(t, m.Path(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
		assert.True(t, bytes.Equal(want, again))
	})

	t.Run("SharedWriteMappingRejected", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, m.Path("files/exact_block"))
		_, err := unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		assert.ErrorIs(t, err, unix.EACCES)
	})
}
