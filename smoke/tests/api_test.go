// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/image-service/smoke/tests/texture"
	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
)

type APIV1TestSuite struct{}

func (a *APIV1TestSuite) TestDaemonStatus(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

	rafs := a.rootFsToRafs(t, ctx, rootFs)

	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
		NydusdPath:          ctx.Binary.Nydusd,
		BootstrapPath:       rafs,
		ConfigPath:          filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		MountPath:           ctx.Env.MountDir,
		APISockPath:         filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		BackendType:         "localfs",
		BackendConfig:       fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		EnablePrefetch:      ctx.Runtime.EnablePrefetch,
		BlobCacheDir:        ctx.Env.CacheDir,
		CacheType:           ctx.Runtime.CacheType,
		CacheCompressed:     ctx.Runtime.CacheCompressed,
		RafsMode:            ctx.Runtime.RafsMode,
		DigestValidate:      false,
		EnableDeduplication: false,
		DeduplicationDir:    "",
	})
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	// The implementation of runNydusd() has checked stats, however,
	// it's clear of semantic to check stats again.
	newCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	select {
	case <-tool.CheckReady(newCtx, nydusd.APISockPath):
		return
	case <-time.After(50 * time.Millisecond):
		require.Fail(t, "nydusd status is not RUNNING")
	}
}

func (a *APIV1TestSuite) TestMetrics(t *testing.T) {

	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

	rafs := a.rootFsToRafs(t, ctx, rootFs)

	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
		NydusdPath:          ctx.Binary.Nydusd,
		BootstrapPath:       rafs,
		ConfigPath:          filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		MountPath:           ctx.Env.MountDir,
		APISockPath:         filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		BackendType:         "localfs",
		BackendConfig:       fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		EnablePrefetch:      ctx.Runtime.EnablePrefetch,
		BlobCacheDir:        ctx.Env.CacheDir,
		CacheType:           ctx.Runtime.CacheType,
		CacheCompressed:     ctx.Runtime.CacheCompressed,
		RafsMode:            ctx.Runtime.RafsMode,
		DigestValidate:      false,
		IOStatsFiles:        true,
		LatestReadFiles:     true,
		AccessPattern:       true,
		EnableDeduplication: false,
		DeduplicationDir:    "",
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

	rafs := a.rootFsToRafs(t, ctx, rootFs)

	config := tool.NydusdConfig{
		NydusdPath:          ctx.Binary.Nydusd,
		MountPath:           ctx.Env.MountDir,
		APISockPath:         filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:          filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		EnableDeduplication: false,
		DeduplicationDir:    "",
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
	time.Sleep(time.Millisecond * 15)

	bcm, err := nydusd.GetBlobCacheMetrics("")
	require.NoError(t, err)
	require.Greater(t, bcm.PrefetchDataAmount, uint64(0))

	_, err = nydusd.GetBlobCacheMetrics("/pseudo_fs_1")
	require.NoError(t, err)
}

func (a *APIV1TestSuite) rootFsToRafs(t *testing.T, ctx *tool.Context, rootFs *tool.Layer) string {
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
