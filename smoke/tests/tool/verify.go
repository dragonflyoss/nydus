// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/log"
	"github.com/stretchr/testify/require"
)

func Verify(t *testing.T, ctx Context, expectedFiles map[string]*File) {
	config := NydusdConfig{
		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
		NydusdPath:      ctx.Binary.Nydusd,
		BootstrapPath:   ctx.Env.BootstrapPath,
		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		BackendType:     "localfs",
		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		BlobCacheDir:    ctx.Env.CacheDir,
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		MountPath:       ctx.Env.MountDir,
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		DigestValidate:  false,
		AmplifyIO:       ctx.Runtime.AmplifyIO,
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

	actualFiles := map[string]*File{}
	err = filepath.WalkDir(ctx.Env.MountDir, func(path string, entry fs.DirEntry, err error) error {
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
