// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/containerd/nydus-snapshotter/pkg/supervisor"
	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/stretchr/testify/require"
)

type Snapshotter struct {
}

type HotUpgradeTestSuite struct {
	t *testing.T
}

func (c *HotUpgradeTestSuite) buildLayer(t *testing.T, ctx *tool.Context, rootFs *tool.Layer) string {
	digest := rootFs.Pack(t,
		converter.PackOption{
			BuilderPath: ctx.Binary.Builder,
			Compressor:  "lz4_block",
			FsVersion:   "5",
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

func (c *HotUpgradeTestSuite) newNydusd(t *testing.T, ctx *tool.Context, bootstrap, name string, upgrade bool) *tool.Nydusd {
	config := tool.NydusdConfig{
		NydusdPath:         ctx.Binary.Nydusd,
		MountPath:          ctx.Env.MountDir,
		APISockPath:        filepath.Join(ctx.Env.WorkDir, fmt.Sprintf("nydusd-api-%s.sock", name)),
		ConfigPath:         filepath.Join(ctx.Env.WorkDir, fmt.Sprintf("nydusd-config.fusedev-%s.json", name)),
		SupervisorSockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-supervisor.sock"),
	}
	if upgrade {
		config.Upgrade = true
	}

	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)

	_, err = nydusd.Run()
	require.NoError(t, err)

	if upgrade {
		err = nydusd.WaitStatus("INIT")
	} else {
		err = nydusd.WaitStatus("RUNNING")
	}
	require.NoError(t, err)

	config.BootstrapPath = bootstrap
	config.MountPath = "/"
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

	return nydusd
}

func (c *HotUpgradeTestSuite) TestHotUpgrade(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Build nydus layer
	layer := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root"))
	bootstrap := c.buildLayer(t, ctx, layer)

	// Start snapshotter simulator
	ss, err := supervisor.NewSupervisorSet(filepath.Join(ctx.Env.WorkDir))
	require.NoError(t, err)
	supervisor := ss.NewSupervisor("nydusd-supervisor")
	defer ss.DestroySupervisor("nydusd-supervisor")

	// Start old nydusd to mount rootfs
	oldNydusd := c.newNydusd(t, ctx, bootstrap, "old", false)
	defer oldNydusd.Umount()

	// Old nydusd's state should be RUNNING
	err = oldNydusd.WaitStatus("RUNNING")
	require.NoError(t, err)

	// Verify filesytem on new nydusd
	oldNydusd.Verify(t, layer.FileTree)

	// Snapshotter receive fuse fd from old nydusd
	err = supervisor.FetchDaemonStates(oldNydusd.SendFd)
	require.NoError(t, err)

	// Start new nydusd in upgrade mode (don't mount)
	newNydusd := c.newNydusd(t, ctx, bootstrap, "new", true)
	defer newNydusd.Umount()

	// New nydusd's state should be INIT
	err = newNydusd.WaitStatus("INIT")
	require.NoError(t, err)

	// Tells old nydusd to exit
	err = oldNydusd.Exit()
	require.NoError(t, err)

	// Send fuse fd to new nydusd
	err = supervisor.SendStatesTimeout(time.Second * 5)
	require.NoError(t, err)
	err = newNydusd.Takeover()
	require.NoError(t, err)

	// New nydusd's state should be RUNNING | READY
	// Only have RUNNING state for older nydusd version (v1.x)
	err = newNydusd.WaitStatus("RUNNING", "READY")
	require.NoError(t, err)

	// Snapshotter receive fuse fd from new nydusd
	err = supervisor.FetchDaemonStates(newNydusd.SendFd)
	require.NoError(t, err)

	// Start new nydusd to serve mountpoint
	// It's unnecessary for older nydusd version (v1.x)
	err = newNydusd.StartByAPI()
	require.NoError(t, err)

	// Verify filesytem on new nydusd
	newNydusd.Verify(t, layer.FileTree)
}

func TestHotUpgrade(t *testing.T) {
	test.Run(t, &HotUpgradeTestSuite{t: t})
}
