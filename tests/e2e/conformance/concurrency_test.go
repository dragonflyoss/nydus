package conformance

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testConcurrency(t *testing.T, m *mounted) {
	t.Run("ParallelReadsAgree", func(t *testing.T) {
		t.Parallel()
		files := []string{"files/large_256k", "files/ten_blocks", "files/sparse_hole", "sparse/alternating_064"}
		want := map[string][]byte{}

		for _, rel := range files {
			want[rel] = m.wantBytes(t, rel)
		}

		const workers, rounds = 16, 4
		errs := make([]error, workers)
		var wg sync.WaitGroup

		for i := range workers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				for round := range rounds {
					rel := files[(i+round)%len(files)]

					got, err := os.ReadFile(m.Path(rel))
					if err == nil && !bytes.Equal(want[rel], got) {
						err = fmt.Errorf("%s: round %d read different bytes", rel, round)
					}

					if err != nil {
						errs[i] = err
						return
					}
				}
			}()
		}

		wg.Wait()

		for _, err := range errs {
			assert.NoError(t, err)
		}
	})

	t.Run("ParallelWalksAgree", func(t *testing.T) {
		t.Parallel()
		const workers = 8
		paths := make([][]string, workers)
		errs := make([]error, workers)
		var wg sync.WaitGroup

		for i := range workers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				errs[i] = filepath.WalkDir(m.Root, func(path string, _ fs.DirEntry, err error) error {
					paths[i] = append(paths[i], path)
					return err
				})
			}()
		}

		wg.Wait()

		for i := range workers {
			if !assert.NoError(t, errs[i]) {
				t.FailNow()
			}

			assert.Equal(t, paths[0], paths[i])
		}
	})

	t.Run("ReadDoesNotChangeTimes", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/small_100b", "dirs/many_entries"} {
			path := m.Path(rel)
			var before, after unix.Stat_t
			if !assert.NoError(t, unix.Stat(path, &before)) {
				t.FailNow()
			}

			if before.Mode&unix.S_IFMT == unix.S_IFDIR {
				_, err := os.ReadDir(path)
				if !assert.NoError(t, err) {
					t.FailNow()
				}
			} else {
				_, err := os.ReadFile(path)
				if !assert.NoError(t, err) {
					t.FailNow()
				}
			}

			if !assert.NoError(t, unix.Stat(path, &after)) {
				t.FailNow()
			}
			if !assert.Equal(t, before.Atim, after.Atim) {
				t.FailNow()
			}
			if !assert.Equal(t, before.Mtim, after.Mtim) {
				t.FailNow()
			}

			assert.Equal(t, before.Ctim, after.Ctim)
		}
	})

	t.Run("StatxReportsNoBirthTime", func(t *testing.T) {
		t.Parallel()
		var stx unix.Statx_t
		if !assert.NoError(t, unix.Statx(unix.AT_FDCWD, m.Path("files/small_100b"), 0, unix.STATX_ALL, &stx)) {
			t.FailNow()
		}
		if !assert.Zero(t, stx.Mask&unix.STATX_BTIME) {
			t.FailNow()
		}
		if !assert.NotZero(t, stx.Mask&unix.STATX_MTIME) {
			t.FailNow()
		}
		if !assert.NotZero(t, stx.Mask&unix.STATX_INO) {
			t.FailNow()
		}

		assert.EqualValues(t, 100, stx.Size)
	})

	t.Run("StatxNoFollowSeesTheLink", func(t *testing.T) {
		t.Parallel()
		rel := "symlinks/link_to_file"
		var stx unix.Statx_t
		if !assert.NoError(t, unix.Statx(unix.AT_FDCWD, m.Path(rel), unix.AT_SYMLINK_NOFOLLOW, unix.STATX_ALL, &stx)) {
			t.FailNow()
		}
		if !assert.EqualValues(t, unix.S_IFLNK, stx.Mode&unix.S_IFMT) {
			t.FailNow()
		}

		assert.EqualValues(t, len("target_file"), stx.Size)
	})

	t.Run("RepeatedStatAgrees", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/large_256k", "hardlinks/link2", "special/chardev", "dirs"} {
			var first, again unix.Stat_t
			if !assert.NoError(t, unix.Lstat(m.Path(rel), &first)) {
				t.FailNow()
			}

			for range 3 {
				if !assert.NoError(t, unix.Lstat(m.Path(rel), &again)) {
					t.FailNow()
				}

				assert.Equal(t, first, again)
			}
		}
	})
}
