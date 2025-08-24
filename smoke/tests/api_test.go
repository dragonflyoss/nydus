// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/BraveY/snapshotter-converter/converter"
	"github.com/containerd/log"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
)

type APIV1TestSuite struct{}

func (a *APIV1TestSuite) TestDaemonStatus(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

	rafs := a.buildLayer(t, ctx, rootFs)

	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
		NydusdPath:      ctx.Binary.Nydusd,
		BootstrapPath:   rafs,
		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		MountPath:       ctx.Env.MountDir,
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		BackendType:     "localfs",
		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
		BlobCacheDir:    ctx.Env.CacheDir,
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		DigestValidate:  false,
	})
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	err = nydusd.WaitStatus("RUNNING")
	require.NoError(t, err)
}

func (a *APIV1TestSuite) TestMetrics(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

	rafs := a.buildLayer(t, ctx, rootFs)

	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
		NydusdPath:      ctx.Binary.Nydusd,
		BootstrapPath:   rafs,
		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		MountPath:       ctx.Env.MountDir,
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		BackendType:     "localfs",
		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
		BlobCacheDir:    ctx.Env.CacheDir,
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		DigestValidate:  false,
		IOStatsFiles:    true,
		LatestReadFiles: true,
		AccessPattern:   true,
	})
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	err = a.visit(filepath.Join(ctx.Env.MountDir, "file-1"))
	require.NoError(t, err)

	gm, err := nydusd.GetGlobalMetrics()
	require.NoError(t, err)
	require.True(t, gm.FilesAccountEnabled)
	require.True(t, gm.MeasureLatency)
	require.True(t, gm.AccessPattern)
	require.Equal(t, uint64(len("file-1")), gm.DataRead)
	require.Equal(t, uint64(1), gm.FOPS[4])

	err = a.visit(filepath.Join(ctx.Env.MountDir, "dir-1/file-1"))
	require.NoError(t, err)
	gmNew, err := nydusd.GetGlobalMetrics()
	require.NoError(t, err)
	require.Equal(t, gm.DataRead+uint64(len("dir-1/file-1")), gmNew.DataRead)
	require.Equal(t, gm.FOPS[4]+1, gmNew.FOPS[4])

	_, err = nydusd.GetFilesMetrics("/")
	require.NoError(t, err)

	_, err = nydusd.GetBackendMetrics("/")
	require.NoError(t, err)

	_, err = nydusd.GetLatestFileMetrics()
	require.NoError(t, err)

	apms, err := nydusd.GetAccessPatternMetrics("/")
	require.NoError(t, err)
	require.NotEmpty(t, apms)

	apms, err = nydusd.GetAccessPatternMetrics("")
	require.NoError(t, err)
	require.NotEmpty(t, apms)

	apms, err = nydusd.GetAccessPatternMetrics("poison")
	require.NoError(t, err)
	require.Empty(t, apms)
}

func (a *APIV1TestSuite) TestPrefetch(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	rootFs := texture.MakeLowerLayer(
		t,
		filepath.Join(ctx.Env.WorkDir, "root-fs"),
		texture.LargerFileMaker("large-blob.bin", 5))

	rafs := a.buildLayer(t, ctx, rootFs)

	config := tool.NydusdConfig{
		NydusdPath:  ctx.Binary.Nydusd,
		MountPath:   ctx.Env.MountDir,
		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
	}
	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	config.BootstrapPath = rafs
	config.MountPath = "/pseudo_fs_1"
	config.BackendType = "localfs"
	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
	config.EnablePrefetch = true
	config.PrefetchFiles = []string{"/"}
	config.BlobCacheDir = ctx.Env.CacheDir
	config.CacheType = ctx.Runtime.CacheType
	config.CacheCompressed = ctx.Runtime.CacheCompressed
	config.RafsMode = ctx.Runtime.RafsMode
	err = nydusd.MountByAPI(config)
	require.NoError(t, err)

	bcm, err := nydusd.GetBlobCacheMetrics("")
	require.NoError(t, err)
	require.Greater(t, bcm.PrefetchDataAmount, uint64(0))

	_, err = nydusd.GetBlobCacheMetrics("/pseudo_fs_1")
	require.NoError(t, err)
}

func (a *APIV1TestSuite) TestSubMountCache(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// lower contains more files than thinLower
	lower := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "rootfs"))
	thinLower := texture.MakeThinLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "rootfs1"))

	lowerBootstrap := a.buildLayer(t, ctx, lower)
	thinLowerBootstrap := a.buildLayer(t, ctx, thinLower)

	config := tool.NydusdConfig{
		NydusdPath:  ctx.Binary.Nydusd,
		MountPath:   ctx.Env.MountDir,
		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
	}

	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)
	defer nydusd.Umount()

	// child mount config template (copied every iteration)
	childTpl := tool.NydusdConfig{
		NydusdPath:      ctx.Binary.Nydusd,
		MountPath:       "/mount",
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		BackendType:     "localfs",
		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		BlobCacheDir:    ctx.Env.CacheDir,
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
		DigestValidate:  false,
		AmplifyIO:       ctx.Runtime.AmplifyIO,
	}

	// mount prefix where the daemon actually mounts sub-mounts
	mountPrefix := ctx.Env.WorkDir + "/mnt"

	// iterate 256 times; first mount uses thinlower (without some files), subsequent mounts use Lower.
	for i := 0; i < 256; i++ {
		curCfg := childTpl
		if i == 0 {
			curCfg.BootstrapPath = thinLowerBootstrap
		} else {
			curCfg.BootstrapPath = lowerBootstrap
		}
		curCfg.MountPath = childTpl.MountPath + fmt.Sprintf("-%d", i)
		err = nydusd.MountByAPI(curCfg)
		require.NoError(t, err, "failed to mount by API at iteration %d", i)

		fullMount := filepath.Join(mountPrefix, curCfg.MountPath)

		// VerifyByPath validates the file tree and also triggers the construction of inode and dentry caches.
		if i == 0 {
			nydusd.VerifyByPath(t, thinLower.FileTree, curCfg.MountPath)
		} else {
			// Verify specific files exist
			_, err := os.Stat(filepath.Join(fullMount, "dir-1/file-1"))
			require.NoError(t, err, "stat file-1 failed")

			// Verify file contents
			data, err := os.ReadFile(filepath.Join(fullMount, "file-2"))
			require.NoError(t, err, "fail to read file-2")
			require.Equal(t, []byte("file-2"), data, "file-2")

			//  Verify directory contents
			ents, err := os.ReadDir(filepath.Join(fullMount, "dir-1"))
			require.NoError(t, err, "readdir dir-1 failed")

			names := make(map[string]bool)
			for _, e := range ents {
				names[e.Name()] = true
			}
			expected := []string{
				"file-1-hardlink-1",
				"file-1-hardlink-2",
				"file-1-symlink-1",
				"file-1-symlink-2",
				"file-external-1",
				"file-2",
			}

			// Ensure directory contains all expected entries
			for _, name := range expected {
				require.True(t, names[name], "dir-1 should contain %s", name)
			}

			nydusd.VerifyByPath(t, lower.FileTree, curCfg.MountPath)

		}
		err = nydusd.UmountByAPI(curCfg.MountPath)
		require.NoError(t, err, "failed to unmount by API at iteration %d", i)
	}
}
func (a *APIV1TestSuite) TestMount(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "rootfs"))

	rafs := a.buildLayer(t, ctx, rootFs)

	config := tool.NydusdConfig{
		NydusdPath:  ctx.Binary.Nydusd,
		MountPath:   ctx.Env.MountDir,
		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
	}
	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)

	config.BootstrapPath = rafs
	config.MountPath = "/mount"
	config.BackendType = "localfs"
	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
	config.BlobCacheDir = ctx.Env.CacheDir
	config.CacheType = ctx.Runtime.CacheType
	config.CacheCompressed = ctx.Runtime.CacheCompressed
	config.RafsMode = ctx.Runtime.RafsMode
	config.EnablePrefetch = ctx.Runtime.EnablePrefetch
	config.DigestValidate = false
	config.AmplifyIO = ctx.Runtime.AmplifyIO
	err = nydusd.MountByAPI(config)
	require.NoError(t, err)

	defer nydusd.Umount()
	defer nydusd.UmountByAPI(config.MountPath)
	nydusd.VerifyByPath(t, rootFs.FileTree, config.MountPath)
}

func (a *APIV1TestSuite) buildLayer(t *testing.T, ctx *tool.Context, rootFs *tool.Layer) string {
	digest := rootFs.Pack(t,
		converter.PackOption{
			BuilderPath: ctx.Binary.Builder,
			Compressor:  ctx.Build.Compressor,
			FsVersion:   ctx.Build.FSVersion,
			ChunkSize:   ctx.Build.ChunkSize,
		},
		ctx.Env.BlobDir)
	_, bootstrap := tool.MergeLayers(t, *ctx,
		converter.MergeOption{
			BuilderPath: ctx.Binary.Builder,
		},
		[]converter.Layer{
			{Digest: digest},
		})
	return bootstrap
}

func (a *APIV1TestSuite) visit(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	io.ReadAll(f)

	return nil
}

func TestAPI(t *testing.T) {
	test.Run(t, &APIV1TestSuite{})
}
