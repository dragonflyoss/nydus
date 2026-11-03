package conformance

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

func testXattr(t *testing.T, m *mounted) {
	t.Run("SizeProbe", func(t *testing.T) {
		t.Parallel()
		size, err := unix.Lgetxattr(m.Path("xattrs/user_long_val"), "user.longval", nil)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, 512, size) {
			t.FailNow()
		}

		want := fstest.ListXattr(t, m.Path("xattrs/user_multi"))
		size, err = unix.Llistxattr(m.Path("xattrs/user_multi"), nil)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, len(strings.Join(want, "\x00"))+1, size)
	})

	t.Run("BufferTooSmall", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Lgetxattr(m.Path("xattrs/user_long_val"), "user.longval", make([]byte, 8))
		if !assert.ErrorIs(t, err, unix.ERANGE) {
			t.FailNow()
		}

		_, err = unix.Lgetxattr(m.Path("xattrs/user_long_val"), "user.longval", make([]byte, 511))
		if !assert.ErrorIs(t, err, unix.ERANGE) {
			t.FailNow()
		}

		_, err = unix.Llistxattr(m.Path("xattrs/user_huge_ibody"), make([]byte, 4))
		assert.ErrorIs(t, err, unix.ERANGE)
	})

	t.Run("MissingAttribute", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"xattrs/user_basic", "files/tiny_2b", "dirs"} {
			_, err := unix.Lgetxattr(m.Path(rel), "user.absent", make([]byte, 64))
			assert.ErrorIs(t, err, unix.ENODATA)
		}
	})

	t.Run("Values", func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, []byte("hello"), fstest.Xattr(t, m.Path("xattrs/user_basic"), "user.test")) {
			t.FailNow()
		}
		if !assert.Empty(t, fstest.Xattr(t, m.Path("xattrs/user_empty_val"), "user.empty")) {
			t.FailNow()
		}

		for _, rel := range []string{"xattrs/user_binary", "xattrs/user_long_name", "xattrs/user_multi", "xattrs/dir_with_xattr"} {
			names := fstest.ListXattr(t, m.src(rel))
			if !assert.NotEmpty(t, names) {
				t.FailNow()
			}
			if !assert.Equal(t, names, fstest.ListXattr(t, m.Path(rel))) {
				t.FailNow()
			}

			for _, name := range names {
				assert.Equal(t, fstest.Xattr(t, m.src(rel), name), fstest.Xattr(t, m.Path(rel), name))
			}
		}
	})

	t.Run("PrivilegedNamespaces", func(t *testing.T) {
		t.Parallel()
		if !assert.Equal(t, []byte("trusted_value"), fstest.Xattr(t, m.Path("xattrs/trusted_attr"), "trusted.test")) {
			t.FailNow()
		}

		assert.Equal(t, []byte("sec_value"), fstest.Xattr(t, m.Path("xattrs/security_attr"), "security.test"))
	})

	t.Run("InlineBodyOverflow", func(t *testing.T) {
		t.Parallel()
		rel := "xattrs/user_huge_ibody"
		if !assert.Len(t, fstest.ListXattr(t, m.Path(rel)), 3) {
			t.FailNow()
		}

		for i := 0; i < 3; i++ {
			name := fmt.Sprintf("user.large_%02d", i)
			assert.Equal(t, fstest.Xattr(t, m.src(rel), name), fstest.Xattr(t, m.Path(rel), name))
		}
	})

	if m.isKernelEROFS() {
		return
	}

	t.Run("InternalNamespaceHidden", func(t *testing.T) {
		t.Parallel()
		for _, name := range fstest.ListXattr(t, m.Root) {
			assert.False(t, strings.HasPrefix(name, "trusted.nydus."))
		}
	})
}
