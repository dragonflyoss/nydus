package contract

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func runDirents(t *testing.T, f *Fixture) {
	t.Run("DotEntries", func(t *testing.T) {
		t.Parallel()
		names := direntNames(fstest.ReadDirents(t, f.Path("dirs/empty_dir"), 32<<10))
		sort.Strings(names)
		assert.Equal(t, []string{".", ".."}, names)
	})

	t.Run("TypeAndInoMatchStat", func(t *testing.T) {
		t.Parallel()
		for _, dir := range []string{"files", "symlinks", "special", "hardlinks", "names", "inode", "dirs"} {
			for _, e := range fstest.ReadDirents(t, f.Path(dir), 32<<10) {
				if e.Name == "." || e.Name == ".." {
					continue
				}

				var st unix.Stat_t
				if !assert.NoError(t, unix.Lstat(filepath.Join(f.Path(dir), e.Name), &st)) {
					t.FailNow()
				}
				if !assert.Equal(t, uint8((st.Mode&unix.S_IFMT)>>12), e.Type) {
					t.FailNow()
				}

				assert.Equal(t, st.Ino, e.Ino)
			}
		}
	})

	t.Run("LargeDirectoryComplete", func(t *testing.T) {
		t.Parallel()
		// 200 entries do not fit in one 4KiB EROFS directory block, so this
		// walks the block-splitting path in the builder.
		got := map[string]int{}

		for _, e := range fstest.ReadDirents(t, f.Path("dirs/many_entries"), 32<<10) {
			got[e.Name]++
		}

		delete(got, ".")
		delete(got, "..")

		if !assert.Len(t, got, 200) {
			t.FailNow()
		}

		for i := 1; i <= 200; i++ {
			name := fmt.Sprintf("file_%04d", i)
			assert.Equal(t, 1, got[name])
		}
	})

	t.Run("SmallBufferYieldsSameStream", func(t *testing.T) {
		t.Parallel()
		// A buffer that only holds a few dirents forces many getdents64 calls
		// and exposes off-by-one errors in the resume offset.
		for _, dir := range []string{"dirs/many_entries", "wide/long"} {
			big := fstest.ReadDirents(t, f.Path(dir), 64<<10)
			small := fstest.ReadDirents(t, f.Path(dir), 512)
			assert.Equal(t, big, small)
		}
	})

	dirs := []string{"dirs/many_entries", "dirs", "dirs/empty_dir", "wide/long"}

	t.Run("OffsetsUnique", func(t *testing.T) {
		t.Parallel()
		for _, rel := range dirs {
			seen := map[int64]string{}

			for _, e := range fstest.ReadDirents(t, f.Path(rel), 4096) {
				_, dup := seen[e.Off]
				if !assert.False(t, dup) {
					t.FailNow()
				}

				seen[e.Off] = e.Name
			}
		}
	})

	t.Run("SeekResumesStream", func(t *testing.T) {
		t.Parallel()
		for _, rel := range dirs {
			fd := openDir(t, f.Path(rel))

			all := fstest.DrainDirents(t, fd, 4096)
			for i := range all {
				var from int64
				if i > 0 {
					from = all[i-1].Off
				}

				_, err := unix.Seek(fd, from, unix.SEEK_SET)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				next := fstest.DrainDirents(t, fd, 4096)
				assert.Equal(t, all[i:], next)
			}

			// Past the last entry there is nothing left.
			_, err := unix.Seek(fd, all[len(all)-1].Off, unix.SEEK_SET)
			assert.NoError(t, err)
			assert.Empty(t, fstest.DrainDirents(t, fd, 4096))
		}
	})

	t.Run("SeekIsRepeatable", func(t *testing.T) {
		t.Parallel()
		fd := openDir(t, f.Path("dirs/many_entries"))
		all := fstest.DrainDirents(t, fd, 4096)
		if !assert.Greater(t, len(all), 10) {
			t.FailNow()
		}

		mid := all[len(all)/2].Off
		var first []fstest.Dirent

		for i := 0; i < 3; i++ {
			_, err := unix.Seek(fd, mid, unix.SEEK_SET)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			got := fstest.DrainDirents(t, fd, 4096)

			if i == 0 {
				first = got
				continue
			}

			assert.Equal(t, first, got)
		}
	})

	t.Run("SeparateHandlesAreIndependent", func(t *testing.T) {
		t.Parallel()
		path := f.Path("dirs/many_entries")
		want := fstest.ReadDirents(t, path, 1<<16)
		a, b := openDir(t, path), openDir(t, path)
		n, err := unix.Getdents(a, make([]byte, 4096))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Positive(t, n)
		// B has never been read, so it must still start from the beginning.
		assert.Equal(t, want, fstest.DrainDirents(t, b, 1<<16))
	})

	t.Run("RewindRepeats", func(t *testing.T) {
		t.Parallel()
		fd := openDir(t, f.Path("dirs/many_entries"))
		want := fstest.DrainDirents(t, fd, 1024)
		_, err := unix.Seek(fd, 0, unix.SEEK_SET)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, want, fstest.DrainDirents(t, fd, 4096))
	})
}

func direntNames(entries []fstest.Dirent) []string {
	names := make([]string, 0, len(entries))

	for _, e := range entries {
		names = append(names, e.Name)
	}

	return names
}
