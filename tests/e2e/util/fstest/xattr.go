package fstest

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// xattrNames lists the xattr names of path itself, not of a symlink target.
func xattrNames(path string) ([]string, error) {
	size, err := unix.Llistxattr(path, nil)
	// A nydus mount of an image without any xattr answers EOPNOTSUPP.
	if errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if err != nil || size == 0 {
		return nil, err
	}

	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}

	var names []string

	for name := range strings.SplitSeq(string(buf[:n]), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}

	return names, nil
}

// listXattrs returns the xattrs of path without following symlinks, less
// the nydus-internal trusted.nydus.* namespace: the builder stamps
// trusted.nydus.prefetch.blobs on the image root, which the FUSE reader
// hides but a root-privileged kernel EROFS mount exposes. It is not part of
// the reproduced tree.
func listXattrs(path string) (map[string]Bytes, error) {
	names, err := xattrNames(path)
	if err != nil {
		return nil, err
	}

	var xattrs map[string]Bytes

	for _, name := range names {
		if strings.HasPrefix(name, "trusted.nydus.") {
			continue
		}

		size, err := unix.Lgetxattr(path, name, nil)
		if err != nil {
			return nil, fmt.Errorf("getxattr %s: %w", name, err)
		}

		value := make([]byte, size)

		if size > 0 {
			if size, err = unix.Lgetxattr(path, name, value); err != nil {
				return nil, fmt.Errorf("getxattr %s: %w", name, err)
			}
		}

		if xattrs == nil {
			xattrs = map[string]Bytes{}
		}

		xattrs[name] = Bytes(value[:size])
	}

	return xattrs, nil
}

// ListXattr lists the sorted xattr names of path itself, not of a symlink
// target, trusted.nydus.* included.
func ListXattr(t testing.TB, path string) []string {
	t.Helper()
	names, err := xattrNames(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	slices.Sort(names)

	return names
}

// Xattr reads an xattr of path itself, not of a symlink target.
func Xattr(t testing.TB, path, name string) []byte {
	t.Helper()
	size, err := unix.Lgetxattr(path, name, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if size == 0 {
		return []byte{}
	}

	buf := make([]byte, size)
	n, err := unix.Lgetxattr(path, name, buf)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return buf[:n]
}
