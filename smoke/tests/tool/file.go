// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/require"
)

type File struct {
	Path     string
	Size     int64
	Mode     os.FileMode
	Rdev     uint64
	Symlink  string
	UID      uint32
	GID      uint32
	Xattrs   map[string]string
	Hash     digest.Digest
	External bool
}

func GetXattrs(t *testing.T, path string) map[string]string {
	xattrs := map[string]string{}
	names, err := xattr.LList(path)
	require.NoError(t, err)
	for _, name := range names {
		data, err := xattr.LGet(path, name)
		require.NoError(t, err)
		xattrs[name] = string(data)
	}
	return xattrs
}

func NewFile(t *testing.T, path, target string) *File {
	stat, err := os.Lstat(path)
	require.NoError(t, err)

	xattrs := GetXattrs(t, path)
	symlink := ""
	if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
		symlink, err = os.Readlink(path)
		require.NoError(t, err)
	}
	_stat := stat.Sys().(*syscall.Stat_t)

	hash := digest.Digest("")
	if stat.Mode().IsRegular() {
		f, err := os.Open(path)
		require.NoError(t, err)
		defer f.Close()
		digester := digest.Canonical.Digester()
		_, err = io.Copy(digester.Hash(), f)
		require.NoError(t, err)
		hash = digester.Digest()
	}

	file := File{
		Path:    target,
		Size:    stat.Size(),
		Mode:    stat.Mode(),
		Symlink: symlink,
		UID:     _stat.Uid,
		GID:     _stat.Gid,
		Xattrs:  xattrs,
		Hash:    hash,
	}

	return &file
}

func (file *File) Compare(t *testing.T, target *File) {
	if file.Mode.IsDir() {
		file.Size = 0
		target.Size = 0
	}
	require.Equal(t, file, target, fmt.Sprintf("unmatched file %s", target.Path))
}
