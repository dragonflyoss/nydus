package contract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C07: extended attributes: the size probe, ERANGE and ENODATA, empty and
// binary values, every namespace a container image carries, and values that
// spill out of the inline xattr body.
func init() {
	Register(Case{ID: "C07", Name: "Xattr", Scope: Semantic, Run: runXattr})
}

func runXattr(t *testing.T, f *Fixture) {
	t.Run("SizeProbe", func(t *testing.T) {
		t.Parallel()
		size, err := unix.Lgetxattr(f.At("xattrs/user_long_val"), "user.longval", nil)
		require.NoError(t, err)
		require.Equal(t, 512, size, "a nil buffer must report the value size")

		want := oracle.ListXattr(t, f.At("xattrs/user_multi"))
		size, err = unix.Llistxattr(f.At("xattrs/user_multi"), nil)
		require.NoError(t, err)
		require.Equal(t, len(strings.Join(want, "\x00"))+1, size, "a nil buffer must report the list size")
	})

	t.Run("BufferTooSmall", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Lgetxattr(f.At("xattrs/user_long_val"), "user.longval", make([]byte, 8))
		require.ErrorIs(t, err, unix.ERANGE)
		_, err = unix.Lgetxattr(f.At("xattrs/user_long_val"), "user.longval", make([]byte, 511))
		require.ErrorIs(t, err, unix.ERANGE, "one byte short")
		_, err = unix.Llistxattr(f.At("xattrs/user_huge_ibody"), make([]byte, 4))
		require.ErrorIs(t, err, unix.ERANGE)
	})

	t.Run("MissingAttribute", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"xattrs/user_basic", "files/tiny_2b", "dirs"} {
			_, err := unix.Lgetxattr(f.At(rel), "user.absent", make([]byte, 64))
			require.ErrorIs(t, err, unix.ENODATA, "%s", rel)
		}
	})

	t.Run("Values", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []byte("hello"), oracle.GetXattr(t, f.At("xattrs/user_basic"), "user.test"))
		require.Empty(t, oracle.GetXattr(t, f.At("xattrs/user_empty_val"), "user.empty"))
		// Binary values, long names and directories: compared with the source.
		for _, rel := range []string{"xattrs/user_binary", "xattrs/user_long_name", "xattrs/user_multi", "xattrs/dir_with_xattr"} {
			names := oracle.ListXattr(t, f.Src(rel))
			require.NotEmpty(t, names, "%s: the source has no xattr", rel)
			require.Equal(t, names, oracle.ListXattr(t, f.At(rel)), "%s: names", rel)
			for _, name := range names {
				require.Equal(t, oracle.GetXattr(t, f.Src(rel), name), oracle.GetXattr(t, f.At(rel), name), "%s: %s", rel, name)
			}
		}
	})

	t.Run("PrivilegedNamespaces", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []byte("trusted_value"), oracle.GetXattr(t, f.At("xattrs/trusted_attr"), "trusted.test"))
		require.Equal(t, []byte("sec_value"), oracle.GetXattr(t, f.At("xattrs/security_attr"), "security.test"))
	})

	t.Run("InlineBodyOverflow", func(t *testing.T) {
		t.Parallel()
		// Three 900 byte values do not fit in the inline xattr body of an
		// EROFS inode, so this exercises the shared-xattr spill path.
		rel := "xattrs/user_huge_ibody"
		require.Len(t, oracle.ListXattr(t, f.At(rel)), 3)
		for i := 0; i < 3; i++ {
			name := fmt.Sprintf("user.large_%02d", i)
			require.Equal(t, oracle.GetXattr(t, f.Src(rel), name), oracle.GetXattr(t, f.At(rel), name), "%s", name)
		}
	})

	// The builder stamps trusted.nydus.* on the root. The FUSE reader hides
	// it; the kernel driver shows trusted.* to root as stored.
	if isKernelEROFS(f) {
		return
	}
	t.Run("InternalNamespaceHidden", func(t *testing.T) {
		t.Parallel()
		for _, name := range oracle.ListXattr(t, f.Root) {
			require.False(t, strings.HasPrefix(name, "trusted.nydus."), "the root exposes %s", name)
		}
	})
}
