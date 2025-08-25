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
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/pkg/xattr"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type File struct {
	Path    string
	Size    int64
	Mode    os.FileMode
	Rdev    uint64
	Symlink string
	UID     uint32
	GID     uint32
	Xattrs  map[string]string
	Hash    digest.Digest
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
		maxRetries := 10
		var lastErr error
		for i := 0; i < maxRetries; i++ {
			var d digest.Digest
			d, lastErr = tryReadAndHash(path)
			if lastErr == nil {
				hash = d
				break
			}

			logrus.Infof("第 %v 次尝试读取文件 %s 失败: %v", i+1, path, lastErr)
			time.Sleep(5 * time.Second)
		}
		require.NoError(t, lastErr, "文件 %s 在所有重试后仍然无法读取", path)
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

func tryReadAndHash(path string) (digest.Digest, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	digester := digest.Canonical.Digester()
	if _, err := io.Copy(digester.Hash(), f); err != nil {
		return "", err
	}

	return digester.Digest(), nil
}

func (file *File) Compare(t *testing.T, target *File) {
	if file.Mode.IsDir() {
		file.Size = 0
		target.Size = 0
	}
	require.Equal(t, file, target, fmt.Sprintf("unmatched file %s", target.Path))
}
