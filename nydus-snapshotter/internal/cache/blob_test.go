/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cache

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
)

func TestBlob_add(t *testing.T) {
	tests := []struct {
		name   string
		link   bool
		info   func(t *testing.T, path string) os.FileInfo
		expect func(t *testing.T, b *blob)
	}{
		{
			name: "count a file's blocks",
			info: func(t *testing.T, path string) os.FileInfo {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				return info
			},
			expect: func(t *testing.T, b *blob) {
				assert := assert.New(t)
				assert.NotZero(b.size)
			},
		},
		{
			name: "count nothing for a file linked elsewhere",
			link: true,
			info: func(t *testing.T, path string) os.FileInfo {
				info, err := os.Stat(path)
				assert.NoError(t, err)
				return info
			},
			expect: func(t *testing.T, b *blob) {
				assert := assert.New(t)
				assert.Zero(b.size)
			},
		},
		{
			name: "count the size of a file whose blocks cannot be told",
			info: func(t *testing.T, path string) os.FileInfo {
				info, err := fs.Stat(fstest.MapFS{"a.blob.meta": &fstest.MapFile{Data: make([]byte, 8192)}}, "a.blob.meta")
				assert.NoError(t, err)
				return info
			},
			expect: func(t *testing.T, b *blob) {
				assert := assert.New(t)
				assert.EqualValues(8192, b.size)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.blob.meta")
			assert.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{1}, 8192), 0o644))
			if tc.link {
				assert.NoError(t, os.Link(path, filepath.Join(dir, "image.blob.meta")))
			}

			b := &blob{id: "a"}
			b.add(path, tc.info(t, path))
			assert.Equal(t, []string{path}, b.files)
			tc.expect(t, b)
		})
	}
}

func TestCacheFile_blobID(t *testing.T) {
	tests := []struct {
		name   string
		file   cacheFile
		expect func(t *testing.T, id string, ok bool)
	}{
		{
			name: "blob data",
			file: "a.blob.data",
			expect: func(t *testing.T, id string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal("a", id)
			},
		},
		{
			name: "blob meta",
			file: "a.blob.meta",
			expect: func(t *testing.T, id string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal("a", id)
			},
		},
		{
			name: "group map",
			file: "a.group.map",
			expect: func(t *testing.T, id string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal("a", id)
			},
		},
		{
			name: "prefetch lock",
			file: "a.prefetch.lock",
			expect: func(t *testing.T, id string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal("a", id)
			},
		},
		{
			name: "file that is no blob",
			file: "a.txt",
			expect: func(t *testing.T, id string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(id)
			},
		},
		{
			name: "suffix without an id",
			file: ".blob.data",
			expect: func(t *testing.T, id string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(id)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := tc.file.blobID()
			tc.expect(t, id, ok)
		})
	}
}
