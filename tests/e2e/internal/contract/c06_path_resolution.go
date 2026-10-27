package contract

import (
	"os"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C06: lookups, symlink resolution and the errors path walking must stop
// with, including the loop shapes of generic/005.
func init() {
	Register(Case{ID: "C06", Name: "PathResolution", Scope: Semantic, Run: runPathResolution})
}

func runPathResolution(t *testing.T, f *Fixture) {
	t.Run("ReadlinkTargets", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string]string{
			"symlinks/link_to_file":      "target_file",
			"symlinks/link_to_dir":       "target_dir",
			"symlinks/relative_link":     "../files/tiny_2b",
			"symlinks/dangling":          "nonexistent_target",
			"symlinks/chain_a":           "chain_b",
			"symlinks/chain_b":           "chain_c",
			"symlinks/link_to_long_name": corpus.LongName('x', 200),
		} {
			got, err := os.Readlink(f.At(rel))
			require.NoError(t, err, "readlink %s", rel)
			require.Equal(t, want, got, "%s", rel)
		}
	})

	t.Run("FollowResolves", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string]string{
			"symlinks/chain_a":           "chain_end",
			"symlinks/relative_link":     "hi",
			"symlinks/link_to_dir/inner": "in_dir",
			"symlinks/link_to_long_name": "long",
		} {
			data, err := os.ReadFile(f.At(rel))
			require.NoError(t, err, "read %s", rel)
			require.Equal(t, want, string(data), "%s", rel)
		}
	})

	t.Run("DanglingSymlink", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(f.At("symlinks/dangling"), &st), "lstat must succeed")
		require.ErrorIs(t, unix.Stat(f.At("symlinks/dangling"), &st), unix.ENOENT)
	})

	t.Run("NoFollow", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Open(f.At("symlinks/link_to_file"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		require.ErrorIs(t, err, unix.ELOOP)
	})

	t.Run("NotADirectory", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.ErrorIs(t, unix.Stat(f.At("files/tiny_2b/child"), &st), unix.ENOTDIR)
		// At cleans the path, which would drop the trailing slash.
		require.ErrorIs(t, unix.Stat(f.At("files/tiny_2b")+"/", &st), unix.ENOTDIR)
	})

	t.Run("NameTooLong", func(t *testing.T) {
		t.Parallel()
		// The kernel FUSE layer only rejects names above FUSE_NAME_MAX (1024),
		// so advertising f_namelen=255 obliges the lookup to enforce NAME_MAX.
		var st unix.Stat_t
		for _, n := range []int{256, 300, 1100} {
			err := unix.Lstat(f.At("files/"+corpus.LongName('z', n)), &st)
			require.ErrorIs(t, err, unix.ENAMETOOLONG, "%d byte name", n)
		}
	})

	t.Run("MaxLengthNameResolves", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(f.At("names/"+corpus.LongName('a', 250)), &st))
		require.NoError(t, unix.Lstat(f.At("wide/long/"+strings.Repeat("0", 255)), &st))
	})

	t.Run("MissingEntry", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.ErrorIs(t, unix.Lstat(f.At("files/definitely_absent"), &st), unix.ENOENT)
		// A prefix of an existing name is not that name.
		require.ErrorIs(t, unix.Lstat(f.At("files/tiny"), &st), unix.ENOENT)
	})

	for _, rel := range []string{"symlinks/self_loop", "symlinks/loop_a", "symlinks/loop_b"} {
		t.Run("Loop/"+strings.TrimPrefix(rel, "symlinks/"), func(t *testing.T) {
			t.Parallel()
			var st unix.Stat_t
			require.ErrorIs(t, unix.Stat(f.At(rel), &st), unix.ELOOP)
			// The link itself is still readable; only following it loops.
			require.NoError(t, unix.Lstat(f.At(rel), &st))
			_, err := os.Readlink(f.At(rel))
			require.NoError(t, err)
		})
	}

	t.Run("ChainBeyondKernelBudget", func(t *testing.T) {
		t.Parallel()
		// The kernel follows at most 40 links, so the tail of a 50-link chain
		// must fail while a short prefix still resolves.
		var st unix.Stat_t
		require.ErrorIs(t, unix.Stat(f.At("symlinks/deep_49"), &st), unix.ELOOP)
		require.NoError(t, unix.Stat(f.At("symlinks/deep_05"), &st))
	})

	t.Run("PathLongerThanPathMax", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		long := f.Root + "/" + strings.Repeat("a/", 3000) + "x"
		require.ErrorIs(t, unix.Stat(long, &st), unix.ENAMETOOLONG)
	})

	t.Run("DotDot", func(t *testing.T) {
		t.Parallel()
		var root, a, parent unix.Stat_t
		require.NoError(t, unix.Stat(f.Root, &root))
		require.NoError(t, unix.Stat(f.At("dirs/a"), &a))
		require.NoError(t, unix.Stat(f.At("dirs/a/b/.."), &parent))
		require.Equal(t, a.Ino, parent.Ino, "dirs/a/b/.. should be dirs/a")
		require.NoError(t, unix.Stat(f.At("dirs/.."), &parent))
		require.Equal(t, root.Ino, parent.Ino, "dirs/.. should be the filesystem root")
		// From inside the mount, ".." of the root leaves the filesystem.
		fd := openDir(t, f.Root)
		require.NoError(t, unix.Fstatat(fd, "..", &parent, 0))
		require.NotEqual(t, root.Dev, parent.Dev, "the root's parent is still on the mount")
	})
}
