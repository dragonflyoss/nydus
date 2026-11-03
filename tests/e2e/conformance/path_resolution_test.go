package conformance

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testPathResolution(t *testing.T, m *mounted) {
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
			got, err := os.Readlink(m.Path(rel))
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
			data, err := os.ReadFile(m.Path(rel))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, want, string(data))
		}
	})

	t.Run("DanglingSymlink", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(m.Path("symlinks/dangling"), &st)) {
			t.FailNow()
		}

		assert.ErrorIs(t, unix.Stat(m.Path("symlinks/dangling"), &st), unix.ENOENT)
	})

	t.Run("NoFollow", func(t *testing.T) {
		t.Parallel()
		assert.ErrorIs(t, openErr(m.Path("symlinks/link_to_file"), unix.O_RDONLY|unix.O_NOFOLLOW, 0), unix.ELOOP)
	})

	t.Run("NotADirectory", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.ErrorIs(t, unix.Stat(m.Path("files/tiny_2b/child"), &st), unix.ENOTDIR) {
			t.FailNow()
		}

		assert.ErrorIs(t, unix.Stat(m.Path("files/tiny_2b")+"/", &st), unix.ENOTDIR)
	})

	t.Run("NameTooLong", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t

		for _, n := range []int{256, 300, 1100} {
			err := unix.Lstat(m.Path("files/"+strings.Repeat("z", n)), &st)
			assert.ErrorIs(t, err, unix.ENAMETOOLONG)
		}
	})

	t.Run("MaxLengthNameResolves", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(m.Path("names/"+strings.Repeat("a", 250)), &st)) {
			t.FailNow()
		}

		assert.NoError(t, unix.Lstat(m.Path("wide/long/"+strings.Repeat("0", 255)), &st))
	})

	t.Run("MissingEntry", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.ErrorIs(t, unix.Lstat(m.Path("files/definitely_absent"), &st), unix.ENOENT) {
			t.FailNow()
		}

		assert.ErrorIs(t, unix.Lstat(m.Path("files/tiny"), &st), unix.ENOENT)
	})

	for _, rel := range []string{"symlinks/self_loop", "symlinks/loop_a", "symlinks/loop_b"} {
		t.Run("Loop/"+strings.TrimPrefix(rel, "symlinks/"), func(t *testing.T) {
			t.Parallel()
			var st unix.Stat_t
			if !assert.ErrorIs(t, unix.Stat(m.Path(rel), &st), unix.ELOOP) {
				t.FailNow()
			}
			if !assert.NoError(t, unix.Lstat(m.Path(rel), &st)) {
				t.FailNow()
			}

			_, err := os.Readlink(m.Path(rel))
			assert.NoError(t, err)
		})
	}

	t.Run("ChainBeyondKernelBudget", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.ErrorIs(t, unix.Stat(m.Path("symlinks/deep_49"), &st), unix.ELOOP) {
			t.FailNow()
		}

		assert.NoError(t, unix.Stat(m.Path("symlinks/deep_05"), &st))
	})

	t.Run("PathLongerThanPathMax", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		long := m.Root + "/" + strings.Repeat("a/", 3000) + "x"
		assert.ErrorIs(t, unix.Stat(long, &st), unix.ENAMETOOLONG)
	})

	t.Run("DotDot", func(t *testing.T) {
		t.Parallel()
		var root, a, parent unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Root, &root)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(m.Path("dirs/a"), &a)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(m.Path("dirs/a/b/.."), &parent)) {
			t.FailNow()
		}
		if !assert.Equal(t, a.Ino, parent.Ino) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(m.Path("dirs/.."), &parent)) {
			t.FailNow()
		}
		if !assert.Equal(t, root.Ino, parent.Ino) {
			t.FailNow()
		}

		fd := openDir(t, m.Root)
		if !assert.NoError(t, unix.Fstatat(fd, "..", &parent, 0)) {
			t.FailNow()
		}

		assert.NotEqual(t, root.Dev, parent.Dev)
	})
}
