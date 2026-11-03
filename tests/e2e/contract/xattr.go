package contract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

func runXattr(t *testing.T, f *Fixture) {
	t.Run("SizeProbe", func(t *testing.T) {
		t.Parallel()
		size, err := unix.Lgetxattr(f.Path("xattrs/user_long_val"), "user.longval", nil)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, 512, size) {
			t.FailNow()
		}

		want := fstest.ListXattr(t, f.Path("xattrs/user_multi"))
		size, err = unix.Llistxattr(f.Path("xattrs/user_multi"), nil)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, len(strings.Join(want, "\x00"))+1, size)
	})

	t.Run("BufferTooSmall", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Lgetxattr(f.Path("xattrs/user_long_val"), "user.longval", make([]byte, 8))
		if !assert.ErrorIs(t, err, unix.ERANGE) {
			t.FailNow()
		}

		_, err = unix.Lgetxattr(f.Path("xattrs/user_long_val"), "user.longval", make([]byte, 511))
		if !assert.ErrorIs(t, err, unix.ERANGE) {
			t.FailNow()
		}

		_, err = unix.Llistxattr(f.Path("xattrs/user_huge_ibody"), make([]byte, 4))
		assert.ErrorIs(t, err, unix.ERANGE)
	})

	t.Run("MissingAttribute", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"xattrs/user_basic", "files/tiny_2b", "dirs"} {
			_, err := unix.Lgetxattr(f.Path(rel), "user.absent", make([]byte, 64))
			assert.ErrorIs(t, err, unix.ENODATA)
		}
	})

	t.Run("Values", func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, []byte("hello"), fstest.GetXattr(t, f.Path("xattrs/user_basic"), "user.test")) {
			t.FailNow()
		}
		if !assert.Empty(t, fstest.GetXattr(t, f.Path("xattrs/user_empty_val"), "user.empty")) {
			t.FailNow()
		}
		// Binary values, long names and directories: compared with the source.
		for _, rel := range []string{"xattrs/user_binary", "xattrs/user_long_name", "xattrs/user_multi", "xattrs/dir_with_xattr"} {
			names := fstest.ListXattr(t, f.Src(rel))
			if !assert.NotEmpty(t, names) {
				t.FailNow()
			}
			if !assert.Equal(t, names, fstest.ListXattr(t, f.Path(rel))) {
				t.FailNow()
			}

			for _, name := range names {
				assert.Equal(t, fstest.GetXattr(t, f.Src(rel), name), fstest.GetXattr(t, f.Path(rel), name))
			}
		}
	})

	t.Run("PrivilegedNamespaces", func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, []byte("trusted_value"), fstest.GetXattr(t, f.Path("xattrs/trusted_attr"), "trusted.test")) {
			t.FailNow()
		}

		assert.Equal(t, []byte("sec_value"), fstest.GetXattr(t, f.Path("xattrs/security_attr"), "security.test"))
	})

	t.Run("InlineBodyOverflow", func(t *testing.T) {
		t.Parallel()
		// Three 900 byte values do not fit in the inline xattr body of an
		// EROFS inode, so this exercises the shared-xattr spill path.
		rel := "xattrs/user_huge_ibody"
		if !assert.Len(t, fstest.ListXattr(t, f.Path(rel)), 3) {
			t.FailNow()
		}

		for i := 0; i < 3; i++ {
			name := fmt.Sprintf("user.large_%02d", i)
			assert.Equal(t, fstest.GetXattr(t, f.Src(rel), name), fstest.GetXattr(t, f.Path(rel), name))
		}
	})

	// The builder stamps trusted.nydus.* on the root. The FUSE reader hides
	// it; the kernel driver shows trusted.* to root as stored.
	if f.isKernelEROFS() {
		return
	}

	t.Run("InternalNamespaceHidden", func(t *testing.T) {
		t.Parallel()
		for _, name := range fstest.ListXattr(t, f.Root) {
			assert.False(t, strings.HasPrefix(name, "trusted.nydus."))
		}
	})
}
