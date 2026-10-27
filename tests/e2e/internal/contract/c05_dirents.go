package contract

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C05: the raw getdents64 stream rather than os.ReadDir, because the fields
// os.ReadDir throws away (d_type, d_ino, d_off) are exactly the ones the
// EROFS directory encoder has to get right; and the directory offset
// protocol of fstests' t_dir_offset2: every d_off is unique, and seeking to
// one resumes the stream at the following entry.
func init() {
	Register(Case{ID: "C05", Name: "Dirents", Scope: Semantic, Run: runDirents})
}

func runDirents(t *testing.T, f *Fixture) {
	t.Run("DotEntries", func(t *testing.T) {
		t.Parallel()
		names := direntNames(oracle.ReadDirents(t, f.At("dirs/empty_dir"), 32<<10))
		sort.Strings(names)
		require.Equal(t, []string{".", ".."}, names)
	})

	t.Run("TypeAndInoMatchStat", func(t *testing.T) {
		t.Parallel()
		for _, dir := range []string{"files", "symlinks", "special", "hardlinks", "names", "inode", "dirs"} {
			for _, e := range oracle.ReadDirents(t, f.At(dir), 32<<10) {
				if e.Name == "." || e.Name == ".." {
					continue
				}
				var st unix.Stat_t
				require.NoError(t, unix.Lstat(filepath.Join(f.At(dir), e.Name), &st))
				require.Equal(t, direntType(st.Mode), e.Type, "%s/%s: d_type does not match st_mode", dir, e.Name)
				require.Equal(t, st.Ino, e.Ino, "%s/%s: d_ino does not match st_ino", dir, e.Name)
			}
		}
	})

	t.Run("LargeDirectoryComplete", func(t *testing.T) {
		t.Parallel()
		// 200 entries do not fit in one 4KiB EROFS directory block, so this
		// walks the block-splitting path in the builder.
		got := map[string]int{}
		for _, e := range oracle.ReadDirents(t, f.At("dirs/many_entries"), 32<<10) {
			got[e.Name]++
		}
		delete(got, ".")
		delete(got, "..")
		require.Len(t, got, 200, "wrong number of entries")
		for i := 1; i <= 200; i++ {
			name := fmt.Sprintf("file_%04d", i)
			require.Equal(t, 1, got[name], "%s appeared %d times", name, got[name])
		}
	})

	t.Run("SmallBufferYieldsSameStream", func(t *testing.T) {
		t.Parallel()
		// A buffer that only holds a few dirents forces many getdents64 calls
		// and exposes off-by-one errors in the resume offset.
		for _, dir := range []string{"dirs/many_entries", "wide/long"} {
			big := oracle.ReadDirents(t, f.At(dir), 64<<10)
			small := oracle.ReadDirents(t, f.At(dir), 512)
			require.Equal(t, big, small, "%s: the stream depends on the buffer size", dir)
		}
	})

	dirs := []string{"dirs/many_entries", "dirs", "dirs/empty_dir", "wide/long"}

	t.Run("OffsetsUnique", func(t *testing.T) {
		t.Parallel()
		for _, rel := range dirs {
			seen := map[int64]string{}
			for _, e := range oracle.ReadDirents(t, f.At(rel), 4096) {
				prev, dup := seen[e.Off]
				require.False(t, dup, "%s: %q and %q share d_off %d", rel, prev, e.Name, e.Off)
				seen[e.Off] = e.Name
			}
		}
	})

	t.Run("SeekResumesStream", func(t *testing.T) {
		t.Parallel()
		for _, rel := range dirs {
			fd := openDir(t, f.At(rel))
			all := oracle.DrainDirents(t, fd, 4096)
			for i := range all {
				var from int64
				if i > 0 {
					from = all[i-1].Off
				}
				_, err := unix.Seek(fd, from, unix.SEEK_SET)
				require.NoError(t, err, "%s: seek to d_off %d", rel, from)
				next := oracle.DrainDirents(t, fd, 4096)
				require.Equal(t, all[i:], next, "%s: resuming at d_off %d", rel, from)
			}
			// Past the last entry there is nothing left.
			_, err := unix.Seek(fd, all[len(all)-1].Off, unix.SEEK_SET)
			require.NoError(t, err)
			require.Empty(t, oracle.DrainDirents(t, fd, 4096), "%s: entries after the last d_off", rel)
		}
	})

	t.Run("SeekIsRepeatable", func(t *testing.T) {
		t.Parallel()
		fd := openDir(t, f.At("dirs/many_entries"))
		all := oracle.DrainDirents(t, fd, 4096)
		require.Greater(t, len(all), 10)
		mid := all[len(all)/2].Off
		var first []oracle.Dirent
		for i := 0; i < 3; i++ {
			_, err := unix.Seek(fd, mid, unix.SEEK_SET)
			require.NoError(t, err)
			got := oracle.DrainDirents(t, fd, 4096)
			if i == 0 {
				first = got
				continue
			}
			require.Equal(t, first, got, "re-seeking to the same d_off gave a different tail")
		}
	})

	t.Run("SeparateHandlesAreIndependent", func(t *testing.T) {
		t.Parallel()
		path := f.At("dirs/many_entries")
		want := oracle.ReadDirents(t, path, 1<<16)
		a, b := openDir(t, path), openDir(t, path)
		n, err := unix.Getdents(a, make([]byte, 4096))
		require.NoError(t, err)
		require.Positive(t, n, "the first read on handle A returned nothing")
		// B has never been read, so it must still start from the beginning.
		require.Equal(t, want, oracle.DrainDirents(t, b, 1<<16), "handle B lost its own position")
	})

	t.Run("RewindRepeats", func(t *testing.T) {
		t.Parallel()
		fd := openDir(t, f.At("dirs/many_entries"))
		want := oracle.DrainDirents(t, fd, 1024)
		_, err := unix.Seek(fd, 0, unix.SEEK_SET)
		require.NoError(t, err)
		require.Equal(t, want, oracle.DrainDirents(t, fd, 4096), "rewinding changed the stream")
	})
}

// openDir opens dir for getdents64 for the rest of the test.
func openDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err, "open %s", dir)
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func direntNames(entries []oracle.Dirent) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}

// direntType is the d_type a dirent of an inode with mode must carry.
func direntType(mode uint32) uint8 {
	types := map[uint32]uint8{
		unix.S_IFREG: unix.DT_REG, unix.S_IFDIR: unix.DT_DIR, unix.S_IFLNK: unix.DT_LNK,
		unix.S_IFIFO: unix.DT_FIFO, unix.S_IFSOCK: unix.DT_SOCK, unix.S_IFCHR: unix.DT_CHR,
		unix.S_IFBLK: unix.DT_BLK,
	}
	if dt, ok := types[mode&unix.S_IFMT]; ok {
		return dt
	}
	return unix.DT_UNKNOWN
}
