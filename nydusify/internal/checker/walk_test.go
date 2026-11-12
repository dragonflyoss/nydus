/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
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

	mockFileNode = fsNode{
		mode:   0o644,
		size:   5,
		uid:    1000,
		gid:    1000,
		hash:   "original",
		xattrs: map[string]string{"user.test": ""},
	}
)

func mockXattrFile(t *testing.T, path string, xattrs map[string][]byte) {
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, value := range xattrs {
		err := unix.Lsetxattr(path, name, value, 0)
		if errIsXattrUnsupported(err) {
			t.Skipf("filesystem does not support xattr %q", name)
		}

		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWalkRootfs(t *testing.T) {
	tests := []struct {
		name     string
		canceled bool
		root     func(t *testing.T) string
		expect   func(t *testing.T, nodes map[string]fsNode, err error)
	}{
		{
			name: "record files, directories and symlinks",
			root: func(t *testing.T) string {
				root := t.TempDir()
				dir := filepath.Join(root, "dir")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}

				file := filepath.Join(dir, "file")
				if err := os.WriteFile(file, []byte("hello"), 0o640); err != nil {
					t.Fatal(err)
				}

				if err := os.Chmod(file, 0o640); err != nil {
					t.Fatal(err)
				}

				if err := unix.Lsetxattr(file, "user.test", []byte("value"), 0); err != nil {
					t.Fatal(err)
				}

				if err := unix.Lsetxattr(file, "user.empty", nil, 0); err != nil {
					t.Fatal(err)
				}

				if err := os.Symlink("dir/file", filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}

				if err := os.Symlink("missing", filepath.Join(root, "dangling")); err != nil {
					t.Fatal(err)
				}

				return root
			},
			expect: func(t *testing.T, nodes map[string]fsNode, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(nodes, 4)
				assert.NotContains(nodes, ".")
				assert.Equal(fsNode{
					mode:   0o640,
					size:   5,
					uid:    uint32(os.Getuid()),
					gid:    uint32(os.Getgid()),
					hash:   "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
					xattrs: map[string]string{"user.test": "value", "user.empty": ""},
				}, nodes["dir/file"])
				assert.True(nodes["dir"].mode.IsDir())
				for name, target := range map[string]string{"link": "dir/file", "dangling": "missing"} {
					node := nodes[name]
					assert.Equal(os.ModeSymlink, node.mode.Type())
					assert.Equal(target, node.symlink)
					assert.Zero(node.size)
					assert.Empty(node.hash)
					assert.Empty(node.xattrs)
				}
			},
		},
		{
			name: "report missing root",
			root: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "absent")
			},
			expect: func(t *testing.T, nodes map[string]fsNode, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Nil(nodes)
			},
		},
		{
			name:     "stop once canceled",
			canceled: true,
			root: func(t *testing.T) string {
				root := t.TempDir()
				mockXattrFile(t, filepath.Join(root, "file"), nil)
				return root
			},
			expect: func(t *testing.T, nodes map[string]fsNode, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Nil(nodes)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}

			nodes, err := walkRootfs(ctx, tc.root(t))
			tc.expect(t, nodes, err)
		})
	}
}

func TestVerifyRootfs(t *testing.T) {
	tests := []struct {
		name   string
		source map[string]fsNode
		target map[string]fsNode
		expect func(t *testing.T, err error)
	}{
		{
			name:   "pass equal nodes",
			source: map[string]fsNode{"file": mockFileNode},
			target: map[string]fsNode{"file": mockFileNode},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "pass empty rootfs",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "reject path missing in target",
			source: map[string]fsNode{"file": {}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `path "file" exists in source but not in target`)
			},
		},
		{
			name:   "reject path missing in source",
			target: map[string]fsNode{"file": {}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `path "file" exists in target but not in source`)
			},
		},
		{
			name:   "reject file type mismatch",
			source: map[string]fsNode{"file": {mode: 0o644}},
			target: map[string]fsNode{"file": {mode: os.ModeDir | 0o644}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": file type mismatch`)
			},
		},
		{
			name:   "reject permission mismatch",
			source: map[string]fsNode{"file": {mode: 0o644}},
			target: map[string]fsNode{"file": {mode: 0o600}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": permission mismatch`)
			},
		},
		{
			name:   "reject setuid mismatch",
			source: map[string]fsNode{"file": {mode: 0o644}},
			target: map[string]fsNode{"file": {mode: os.ModeSetuid | 0o644}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": special bits mismatch`)
			},
		},
		{
			name:   "reject setgid mismatch",
			source: map[string]fsNode{"file": {mode: 0o644}},
			target: map[string]fsNode{"file": {mode: os.ModeSetgid | 0o644}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": special bits mismatch`)
			},
		},
		{
			name:   "reject sticky mismatch",
			source: map[string]fsNode{"file": {mode: 0o644}},
			target: map[string]fsNode{"file": {mode: os.ModeSticky | 0o644}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": special bits mismatch`)
			},
		},
		{
			name:   "reject uid mismatch",
			source: map[string]fsNode{"file": {uid: 1000}},
			target: map[string]fsNode{"file": {uid: 1001}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": uid mismatch`)
			},
		},
		{
			name:   "reject gid mismatch",
			source: map[string]fsNode{"file": {gid: 1000}},
			target: map[string]fsNode{"file": {gid: 1001}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": gid mismatch`)
			},
		},
		{
			name:   "reject size mismatch",
			source: map[string]fsNode{"file": {size: 5}},
			target: map[string]fsNode{"file": {size: 6}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": size mismatch`)
			},
		},
		{
			name:   "reject content mismatch",
			source: map[string]fsNode{"file": {hash: "original"}},
			target: map[string]fsNode{"file": {hash: "different"}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": content mismatch`)
			},
		},
		{
			name:   "reject xattr missing in target",
			source: map[string]fsNode{"file": {xattrs: map[string]string{"user.test": ""}}},
			target: map[string]fsNode{"file": {}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": xattr "user.test" present in source but missing in target`)
			},
		},
		{
			name:   "reject xattr missing in source",
			source: map[string]fsNode{"file": {}},
			target: map[string]fsNode{"file": {xattrs: map[string]string{"user.test": ""}}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": xattr "user.test" present in target but missing in source`)
			},
		},
		{
			name:   "reject xattr value mismatch",
			source: map[string]fsNode{"file": {xattrs: map[string]string{"user.test": ""}}},
			target: map[string]fsNode{"file": {xattrs: map[string]string{"user.test": "changed"}}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": xattr "user.test" value mismatch`)
			},
		},
		{
			name:   "reject symlink target mismatch",
			source: map[string]fsNode{"file": {mode: os.ModeSymlink | 0o777, symlink: "original"}},
			target: map[string]fsNode{"file": {mode: os.ModeSymlink | 0o777, symlink: "different"}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": symlink target mismatch`)
			},
		},
		{
			name:   "reject character device id mismatch",
			source: map[string]fsNode{"file": {mode: os.ModeDevice | os.ModeCharDevice | 0o600, rdev: 1}},
			target: map[string]fsNode{"file": {mode: os.ModeDevice | os.ModeCharDevice | 0o600, rdev: 2}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": device id mismatch`)
			},
		},
		{
			name:   "reject block device id mismatch",
			source: map[string]fsNode{"file": {mode: os.ModeDevice | 0o600, rdev: 1}},
			target: map[string]fsNode{"file": {mode: os.ModeDevice | 0o600, rdev: 2}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `path "file": device id mismatch`)
			},
		},
		{
			name:   "ignore directory size",
			source: map[string]fsNode{"file": {mode: os.ModeDir | 0o755, size: 4096}},
			target: map[string]fsNode{"file": {mode: os.ModeDir | 0o755, size: 128}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "treat nil and empty xattrs as equal",
			source: map[string]fsNode{"file": {xattrs: nil}},
			target: map[string]fsNode{"file": {xattrs: map[string]string{}}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, verifyRootfs(tc.source, tc.target))
		})
	}
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
		name     string
		canceled bool
		path     func(t *testing.T) string
		expect   func(t *testing.T, hash string, err error)
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
		{
			name:     "stop once canceled",
			canceled: true,
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "file")
				mockXattrFile(t, path, nil)
				return path
			},
			expect: func(t *testing.T, hash string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Empty(hash)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}

			hash, err := hashFile(ctx, tc.path(t))
			tc.expect(t, hash, err)
		})
	}
}

func TestContextReader_Read(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, data []byte, err error)
	}{
		{
			name: "stop between two reads",
			expect: func(t *testing.T, data []byte, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal("first", string(data))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Each read cancels, so only the first one gets through.
			reader := contextReader{ctx: ctx, Reader: mockReader(func(data []byte) (int, error) {
				cancel()
				return copy(data, "first"), nil
			})}

			data, err := io.ReadAll(reader)
			tc.expect(t, data, err)
		})
	}
}

// mockReader makes a function an io.Reader.
type mockReader func([]byte) (int, error)

func (r mockReader) Read(data []byte) (int, error) { return r(data) }

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
