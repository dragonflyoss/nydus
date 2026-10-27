package contract

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C11: concurrent readers agree, and what can never change does not:
// timestamps stay put and repeated queries give the same answer.
func init() {
	Register(Case{ID: "C11", Name: "Concurrency", Scope: Semantic, Run: runConcurrency})
}

func runConcurrency(t *testing.T, f *Fixture) {
	t.Run("ParallelReadsAgree", func(t *testing.T) {
		t.Parallel()
		files := []string{"files/large_256k", "files/ten_blocks", "files/sparse_hole", "sparse/alternating_064"}
		want := map[string][]byte{}
		for _, rel := range files {
			want[rel] = wantBytes(t, f, rel)
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
					got, err := os.ReadFile(f.At(rel))
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
		for i, err := range errs {
			require.NoError(t, err, "worker %d", i)
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
				errs[i] = filepath.WalkDir(f.Root, func(path string, _ fs.DirEntry, err error) error {
					paths[i] = append(paths[i], path)
					return err
				})
			}()
		}
		wg.Wait()
		for i := range workers {
			require.NoError(t, errs[i], "walk %d", i)
			require.Equal(t, paths[0], paths[i], "concurrent walks saw different trees")
		}
	})

	t.Run("ReadDoesNotChangeTimes", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/small_100b", "dirs/many_entries"} {
			path := f.At(rel)
			var before, after unix.Stat_t
			require.NoError(t, unix.Stat(path, &before))
			if before.Mode&unix.S_IFMT == unix.S_IFDIR {
				_, err := os.ReadDir(path)
				require.NoError(t, err)
			} else {
				_, err := os.ReadFile(path)
				require.NoError(t, err)
			}
			require.NoError(t, unix.Stat(path, &after))
			require.Equal(t, before.Atim, after.Atim, "%s: a read-only mount must not advance atime", rel)
			require.Equal(t, before.Mtim, after.Mtim, "%s: mtime", rel)
			require.Equal(t, before.Ctim, after.Ctim, "%s: ctime", rel)
		}
	})

	t.Run("StatxReportsNoBirthTime", func(t *testing.T) {
		t.Parallel()
		// EROFS stores no creation time, so neither reader may claim one.
		var stx unix.Statx_t
		require.NoError(t, unix.Statx(unix.AT_FDCWD, f.At("files/small_100b"), 0, unix.STATX_ALL, &stx))
		require.Zero(t, stx.Mask&unix.STATX_BTIME, "btime reported but EROFS has none")
		require.NotZero(t, stx.Mask&unix.STATX_MTIME)
		require.NotZero(t, stx.Mask&unix.STATX_INO)
		require.EqualValues(t, 100, stx.Size)
	})

	t.Run("StatxNoFollowSeesTheLink", func(t *testing.T) {
		t.Parallel()
		rel := "symlinks/link_to_file"
		var stx unix.Statx_t
		require.NoError(t, unix.Statx(unix.AT_FDCWD, f.At(rel), unix.AT_SYMLINK_NOFOLLOW, unix.STATX_ALL, &stx))
		require.EqualValues(t, unix.S_IFLNK, stx.Mode&unix.S_IFMT)
		require.EqualValues(t, len("target_file"), stx.Size, "a symlink's size is its target length")
	})

	t.Run("RepeatedStatAgrees", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/large_256k", "hardlinks/link2", "special/chardev", "dirs"} {
			var first, again unix.Stat_t
			require.NoError(t, unix.Lstat(f.At(rel), &first))
			for range 3 {
				require.NoError(t, unix.Lstat(f.At(rel), &again))
				require.Equal(t, first, again, "%s: stat changed between calls", rel)
			}
		}
	})
}
