// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type OverlayFsTestSuite struct {
	t *testing.T
}

func (ts *OverlayFsTestSuite) prepareTestEnv(t *testing.T) *tool.Context {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)

	packOption := converter.PackOption{
		BuilderPath: ctx.Binary.Builder,
		Compressor:  ctx.Build.Compressor,
		FsVersion:   ctx.Build.FSVersion,
		ChunkSize:   ctx.Build.ChunkSize,
	}

	lowerLayer := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "lower"))
	lowerBlobDigest := lowerLayer.Pack(t, packOption, ctx.Env.BlobDir)
	mergeOption := converter.MergeOption{
		BuilderPath:   ctx.Binary.Builder,
		ChunkDictPath: "",
		OCIRef:        true,
	}
	actualDigests, lowerBootstrap := tool.MergeLayers(t, *ctx, mergeOption, []converter.Layer{
		{
			Digest: lowerBlobDigest,
		},
	})
	require.Equal(t, []digest.Digest{lowerBlobDigest}, actualDigests)

	// Verify lower layer mounted by nydusd
	ctx.Env.BootstrapPath = lowerBootstrap
	tool.Verify(t, *ctx, lowerLayer.FileTree)

	return ctx
}

func (ts *OverlayFsTestSuite) TestSimpleOverlayFs(t *testing.T) {
	ctx := ts.prepareTestEnv(t)
	fmt.Printf("Workdir is %v\n", ctx.Env.WorkDir)
	defer ctx.Destroy(t)

	nydusd, err := tool.NewNydusdWithOverlay(tool.NydusdConfig{
		NydusdPath:      ctx.Binary.Nydusd,
		BootstrapPath:   ctx.Env.BootstrapPath,
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
		OvlUpperDir:     ctx.Env.OvlUpperDir,
		OvlWorkDir:      ctx.Env.OvlWorkDir,
		DigestValidate:  false,
		Writable:        true,
	})
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	// Write some file under mounted dir.
	mountedDir := ctx.Env.MountDir
	file := filepath.Join(mountedDir, "test.txt")
	err = os.WriteFile(file, []byte("hello world"), 0644)
	require.NoError(t, err)

	// Read it back
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))

	// Try to read from upper dir.
	upperFile := filepath.Join(ctx.Env.OvlUpperDir, "test.txt")
	data, err = os.ReadFile(upperFile)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))
}

func TestOverlayFs(t *testing.T) {
	test.Run(t, &OverlayFsTestSuite{t: t})
}
