// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/log"
	"github.com/stretchr/testify/require"
)

func Verify(t *testing.T, ctx Context, expectedFiles map[string]*File) {
	config := NydusdConfig{
		NydusdPath:  ctx.Binary.Nydusd,
		MountPath:   ctx.Env.MountDir,
		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
	}

	nydusd, err := NewNydusd(config)
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)

	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	config.EnablePrefetch = ctx.Runtime.EnablePrefetch
	config.BootstrapPath = ctx.Env.BootstrapPath
	config.MountPath = "/"
	config.BackendType = "localfs"
	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
	config.BlobCacheDir = ctx.Env.CacheDir
	config.CacheType = ctx.Runtime.CacheType
	config.CacheCompressed = ctx.Runtime.CacheCompressed
	config.RafsMode = ctx.Runtime.RafsMode
	config.DigestValidate = false
	config.AmplifyIO = ctx.Runtime.AmplifyIO

	err = nydusd.MountByAPI(config)
	require.NoError(t, err)
	time.Sleep(time.Millisecond * 15)

	actualFiles := map[string]*File{}
	err = filepath.WalkDir(ctx.Env.MountDir, func(path string, _ fs.DirEntry, err error) error {
		require.Nil(t, err)
		targetPath, err := filepath.Rel(ctx.Env.MountDir, path)
		require.NoError(t, err)
		file := NewFile(t, path, targetPath)
		actualFiles[targetPath] = file
		if expectedFiles[targetPath] != nil {
			expectedFiles[targetPath].Compare(t, file)
		} else {
			t.Fatalf("not found file %s in OCI layer", targetPath)
		}

		return nil
	})
	require.NoError(t, err)

	for targetPath, file := range expectedFiles {
		if actualFiles[targetPath] != nil {
			actualFiles[targetPath].Compare(t, file)
		} else {
			t.Fatalf("not found file %s in nydus layer", targetPath)
		}
	}
}
