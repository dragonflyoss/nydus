/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var (
	mockPosixACL = []byte{
		0x02, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff,
		0x02, 0x00, 0x04, 0x00, 0xd2, 0x04, 0x00, 0x00,
		0x04, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff,
		0x10, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff,
		0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	}
)

func mockXattrFile(t *testing.T, path string, xattrs map[string][]byte) {
	if !assert.NoError(t, os.WriteFile(path, []byte("hello"), 0o644)) {
		t.FailNow()
	}

	for name, value := range xattrs {
		err := unix.Lsetxattr(path, name, value, 0)
		if errIsXattrUnsupported(err) {
			t.Skipf("filesystem does not support xattr %q", name)
		}

		if !assert.NoError(t, err) {
			t.FailNow()
		}
	}
}

func TestVerifyRootfs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fsNode, *fsNode)
		want   string
	}{
		{"equal", func(_, _ *fsNode) {}, ""},
		{"type", func(_, dst *fsNode) { dst.mode |= os.ModeDir }, "file type mismatch"},
		{"permissions", func(_, dst *fsNode) { dst.mode = 0o600 }, "permission mismatch"},
		{"setuid", func(_, dst *fsNode) { dst.mode |= os.ModeSetuid }, "special bits mismatch"},
		{"setgid", func(_, dst *fsNode) { dst.mode |= os.ModeSetgid }, "special bits mismatch"},
		{"sticky", func(_, dst *fsNode) { dst.mode |= os.ModeSticky }, "special bits mismatch"},
		{"uid", func(_, dst *fsNode) { dst.uid++ }, "uid mismatch"},
		{"gid", func(_, dst *fsNode) { dst.gid++ }, "gid mismatch"},
		{"size", func(_, dst *fsNode) { dst.size++ }, "size mismatch"},
		{"content", func(_, dst *fsNode) { dst.hash = "different" }, "content mismatch"},
		{"missing xattr", func(_, dst *fsNode) { dst.xattrs = nil }, "present in source but missing in target"},
		{"extra xattr", func(src, _ *fsNode) { src.xattrs = nil }, "present in target but missing in source"},
		{"xattr value", func(_, dst *fsNode) { dst.xattrs = map[string]string{"user.test": "changed"} }, "value mismatch"},
		{"symlink", func(src, dst *fsNode) {
			*src = fsNode{mode: os.ModeSymlink | 0o777, symlink: "original"}
			*dst = fsNode{mode: os.ModeSymlink | 0o777, symlink: "different"}
		}, "symlink target mismatch"},
		{"character device", func(src, dst *fsNode) {
			*src = fsNode{mode: os.ModeDevice | os.ModeCharDevice | 0o600, rdev: 1}
			*dst = fsNode{mode: os.ModeDevice | os.ModeCharDevice | 0o600, rdev: 2}
		}, "device id mismatch"},
		{"block device", func(src, dst *fsNode) {
			*src = fsNode{mode: os.ModeDevice | 0o600, rdev: 1}
			*dst = fsNode{mode: os.ModeDevice | 0o600, rdev: 2}
		}, "device id mismatch"},
		{"directory size ignored", func(src, dst *fsNode) {
			*src = fsNode{mode: os.ModeDir | 0o755, size: 4096}
			*dst = fsNode{mode: os.ModeDir | 0o755, size: 128}
		}, ""},
		{"empty xattrs", func(src, dst *fsNode) {
			*src = fsNode{xattrs: nil}
			*dst = fsNode{xattrs: map[string]string{}}
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := fsNode{mode: 0o644, size: 5, uid: 1000, gid: 1000, hash: "original", xattrs: map[string]string{"user.test": ""}}
			dst := src
			require.NoError(t, verifyRootfs(map[string]fsNode{"file": src}, map[string]fsNode{"file": dst}))
			tc.change(&src, &dst)
			err := verifyRootfs(map[string]fsNode{"file": src}, map[string]fsNode{"file": dst})
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.want)
				require.ErrorContains(t, err, `path "file"`)
			}
		})
	}
	t.Run("missing and extra paths", func(t *testing.T) {
		nodes := map[string]fsNode{"file": {}}
		require.ErrorContains(t, verifyRootfs(nodes, nil), `path "file" exists in source but not in target`)
		require.ErrorContains(t, verifyRootfs(nil, nodes), `path "file" exists in target but not in source`)
		require.NoError(t, verifyRootfs(nil, nil))
	})
}

func TestWalkRootfs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dir")
	require.NoError(t, os.Mkdir(dir, 0o755))
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("hello"), 0o640))
	require.NoError(t, os.Chmod(file, 0o640))
	require.NoError(t, unix.Lsetxattr(file, "user.test", []byte("value"), 0))
	require.NoError(t, unix.Lsetxattr(file, "user.empty", nil, 0))
	require.NoError(t, os.Symlink("dir/file", filepath.Join(root, "link")))
	require.NoError(t, os.Symlink("missing", filepath.Join(root, "dangling")))

	nodes, err := walkRootfs(root)
	require.NoError(t, err)
	require.Len(t, nodes, 4)
	require.NotContains(t, nodes, ".")
	require.Equal(t, fsNode{
		mode: 0o640, size: 5, uid: uint32(os.Getuid()), gid: uint32(os.Getgid()),
		hash:   "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		xattrs: map[string]string{"user.test": "value", "user.empty": ""},
	}, nodes["dir/file"])
	require.True(t, nodes["dir"].mode.IsDir())
	for name, target := range map[string]string{"link": "dir/file", "dangling": "missing"} {
		node := nodes[name]
		require.Equal(t, os.ModeSymlink, node.mode.Type())
		require.Equal(t, target, node.symlink)
		require.Zero(t, node.size)
		require.Empty(t, node.hash)
		require.Empty(t, node.xattrs)
	}

	_, err = walkRootfs(filepath.Join(root, "absent"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadXattrs(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, path string)
		expect func(t *testing.T, xattrs map[string]string, err error)
	}{
		{
			name: "file without xattrs",
			setup: func(t *testing.T, path string) {
				mockXattrFile(t, path, nil)
			},
			expect: func(t *testing.T, xattrs map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(xattrs)
			},
		},
		{
			name: "user xattrs",
			setup: func(t *testing.T, path string) {
				mockXattrFile(t, path, map[string][]byte{"user.a": []byte("1"), "user.b": nil})
			},
			expect: func(t *testing.T, xattrs map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]string{"user.a": "1", "user.b": ""}, xattrs)
			},
		},
		{
			name: "skip posix acl",
			setup: func(t *testing.T, path string) {
				mockXattrFile(t, path, map[string][]byte{"system.posix_acl_access": mockPosixACL})
			},
			expect: func(t *testing.T, xattrs map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(xattrs)
			},
		},
		{
			name: "keep user xattrs beside posix acl",
			setup: func(t *testing.T, path string) {
				mockXattrFile(t, path, map[string][]byte{"system.posix_acl_access": mockPosixACL, "user.a": []byte("1")})
			},
			expect: func(t *testing.T, xattrs map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]string{"user.a": "1"}, xattrs)
			},
		},
		{
			name:  "missing file",
			setup: func(t *testing.T, path string) {},
			expect: func(t *testing.T, xattrs map[string]string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "list xattr size")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Nil(xattrs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			tc.setup(t, path)
			xattrs, err := readXattrs(path)
			tc.expect(t, xattrs, err)
		})
	}
}

func TestGetXattr(t *testing.T) {
	tests := []struct {
		name   string
		xattr  string
		expect func(t *testing.T, value string, err error)
	}{
		{
			name:  "read value",
			xattr: "user.a",
			expect: func(t *testing.T, value string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("1", value)
			},
		},
		{
			name:  "missing attribute",
			xattr: "user.absent",
			expect: func(t *testing.T, value string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, unix.ENODATA)
				assert.Empty(value)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			mockXattrFile(t, path, map[string][]byte{"user.a": []byte("1")})
			value, err := getXattr(path, tc.xattr)
			tc.expect(t, value, err)
		})
	}
}

func TestHashFile(t *testing.T) {
	tests := []struct {
		name   string
		path   func(t *testing.T) string
		expect func(t *testing.T, hash string, err error)
	}{
		{
			name: "regular file",
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "file")
				mockXattrFile(t, path, nil)
				return path
			},
			expect: func(t *testing.T, hash string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash)
			},
		},
		{
			name: "missing file",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "absent")
			},
			expect: func(t *testing.T, hash string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(hash)
			},
		},
		{
			name: "directory",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, hash string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.EISDIR)
				assert.Empty(hash)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := hashFile(tc.path(t))
			tc.expect(t, hash, err)
		})
	}
}

func TestErrIsXattrUnsupported(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect func(t *testing.T, unsupported bool)
	}{
		{
			name: "not supported",
			err:  unix.ENOTSUP,
			expect: func(t *testing.T, unsupported bool) {
				assert := assert.New(t)
				assert.True(unsupported)
			},
		},
		{
			name: "operation not supported",
			err:  unix.EOPNOTSUPP,
			expect: func(t *testing.T, unsupported bool) {
				assert := assert.New(t)
				assert.True(unsupported)
			},
		},
		{
			name: "wrapped not supported",
			err:  errors.Wrap(unix.ENOTSUP, "list xattr"),
			expect: func(t *testing.T, unsupported bool) {
				assert := assert.New(t)
				assert.True(unsupported)
			},
		},
		{
			name: "missing attribute",
			err:  unix.ENODATA,
			expect: func(t *testing.T, unsupported bool) {
				assert := assert.New(t)
				assert.False(unsupported)
			},
		},
		{
			name: "no error",
			expect: func(t *testing.T, unsupported bool) {
				assert := assert.New(t)
				assert.False(unsupported)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, errIsXattrUnsupported(tc.err))
		})
	}
}
