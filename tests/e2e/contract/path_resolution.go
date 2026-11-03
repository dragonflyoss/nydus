package contract

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

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
			"symlinks/link_to_long_name": strings.Repeat("x", 200),
		} {
			got, err := os.Readlink(f.Path(rel))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, want, got)
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
			data, err := os.ReadFile(f.Path(rel))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, want, string(data))
		}
	})

	t.Run("DanglingSymlink", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(f.Path("symlinks/dangling"), &st)) {
			t.FailNow()
		}

		assert.ErrorIs(t, unix.Stat(f.Path("symlinks/dangling"), &st), unix.ENOENT)
	})

	t.Run("NoFollow", func(t *testing.T) {
		t.Parallel()
		assert.ErrorIs(t, openErr(f.Path("symlinks/link_to_file"), unix.O_RDONLY|unix.O_NOFOLLOW, 0), unix.ELOOP)
	})

	t.Run("NotADirectory", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.ErrorIs(t, unix.Stat(f.Path("files/tiny_2b/child"), &st), unix.ENOTDIR) {
			t.FailNow()
		}
		// Path cleans the path, which would drop the trailing slash.
		assert.ErrorIs(t, unix.Stat(f.Path("files/tiny_2b")+"/", &st), unix.ENOTDIR)
	})

	t.Run("NameTooLong", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t

		for _, n := range []int{256, 300, 1100} {
			err := unix.Lstat(f.Path("files/"+strings.Repeat("z", n)), &st)
			assert.ErrorIs(t, err, unix.ENAMETOOLONG)
		}
	})

	t.Run("MaxLengthNameResolves", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(f.Path("names/"+strings.Repeat("a", 250)), &st)) {
			t.FailNow()
		}

		assert.NoError(t, unix.Lstat(f.Path("wide/long/"+strings.Repeat("0", 255)), &st))
	})

	t.Run("MissingEntry", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.ErrorIs(t, unix.Lstat(f.Path("files/definitely_absent"), &st), unix.ENOENT) {
			t.FailNow()
		}
		// A prefix of an existing name is not that name.
		assert.ErrorIs(t, unix.Lstat(f.Path("files/tiny"), &st), unix.ENOENT)
	})

	for _, rel := range []string{"symlinks/self_loop", "symlinks/loop_a", "symlinks/loop_b"} {
		t.Run("Loop/"+strings.TrimPrefix(rel, "symlinks/"), func(t *testing.T) {
			t.Parallel()
			var st unix.Stat_t
			if !assert.ErrorIs(t, unix.Stat(f.Path(rel), &st), unix.ELOOP) {
				t.FailNow()
			}
			// The link itself is still readable; only following it loops.
			if !assert.NoError(t, unix.Lstat(f.Path(rel), &st)) {
				t.FailNow()
			}

			_, err := os.Readlink(f.Path(rel))
			assert.NoError(t, err)
		})
	}

	t.Run("ChainBeyondKernelBudget", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.ErrorIs(t, unix.Stat(f.Path("symlinks/deep_49"), &st), unix.ELOOP) {
			t.FailNow()
		}

		assert.NoError(t, unix.Stat(f.Path("symlinks/deep_05"), &st))
	})

	t.Run("PathLongerThanPathMax", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		long := f.Root + "/" + strings.Repeat("a/", 3000) + "x"
		assert.ErrorIs(t, unix.Stat(long, &st), unix.ENAMETOOLONG)
	})

	t.Run("DotDot", func(t *testing.T) {
		t.Parallel()
		var root, a, parent unix.Stat_t
		if !assert.NoError(t, unix.Stat(f.Root, &root)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(f.Path("dirs/a"), &a)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(f.Path("dirs/a/b/.."), &parent)) {
			t.FailNow()
		}
		if !assert.Equal(t, a.Ino, parent.Ino) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(f.Path("dirs/.."), &parent)) {
			t.FailNow()
		}
		if !assert.Equal(t, root.Ino, parent.Ino) {
			t.FailNow()
		}
		// From inside the mount, ".." of the root leaves the filesystem.
		fd := openDir(t, f.Root)
		if !assert.NoError(t, unix.Fstatat(fd, "..", &parent, 0)) {
			t.FailNow()
		}

		assert.NotEqual(t, root.Dev, parent.Dev)
	})
}
