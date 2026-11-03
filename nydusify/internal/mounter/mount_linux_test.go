/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package mounter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestPrepareMountpoint(t *testing.T) {
	tests := []struct {
		name   string
		path   func(t *testing.T) (string, string)
		expect func(t *testing.T, want, mountpoint string, err error)
	}{
		{
			name: "symlink resolves to directory",
			path: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				target := filepath.Join(dir, "mnt")
				link := filepath.Join(dir, "link")
				assert.NoError(t, os.Mkdir(target, 0o700))
				assert.NoError(t, os.Symlink(target, link))
				return link, target
			},
			expect: func(t *testing.T, want, mountpoint string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				resolved, err := filepath.EvalSymlinks(want)
				assert.NoError(err)
				assert.Equal(resolved, mountpoint)
			},
		},
		{
			name: "mounted path is rejected",
			path: func(t *testing.T) (string, string) {
				return "/", ""
			},
			expect: func(t *testing.T, want, mountpoint string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `mountpoint "/" is already mounted`)
				assert.Empty(mountpoint)
			},
		},
		{
			name: "missing path",
			path: func(t *testing.T) (string, string) {
				return filepath.Join(t.TempDir(), "missing"), ""
			},
			expect: func(t *testing.T, want, mountpoint string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve mountpoint")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(mountpoint)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, want := tc.path(t)
			mountpoint, err := prepareMountpoint(path)
			tc.expect(t, want, mountpoint, err)
		})
	}
}

func TestUnmountExitedFuse(t *testing.T) {
	tests := []struct {
		name   string
		path   func(t *testing.T) string
		expect func(t *testing.T, path string, err error)
	}{
		{
			name: "missing mountpoint is ignored",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing")
			},
			expect: func(t *testing.T, path string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "healthy directory is left alone",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, path string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(path)
			},
		},
		{
			name: "path through a regular file",
			path: func(t *testing.T) string {
				file := filepath.Join(t.TempDir(), "file")
				assert.NoError(t, os.WriteFile(file, nil, 0o600))
				return filepath.Join(file, "mnt")
			},
			expect: func(t *testing.T, path string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, unix.ENOTDIR)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path(t)
			tc.expect(t, path, unmountExitedFuse(path, "nydusify-test"))
		})
	}
}
