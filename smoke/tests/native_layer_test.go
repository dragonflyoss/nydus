// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"path/filepath"
	"testing"

	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/image-service/smoke/tests/texture"
	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

const (
	paramCompressor      = "compressor"
	paramFSVersion       = "fs_version"
	paramChunkSize       = "chunk_size"
	paramCacheType       = "cache_type"
	paramCacheCompressed = "cache_compressed"
	paramRafsMode        = "rafs_mode"
	paramEnablePrefetch  = "enable_prefetch"
)

type NativeLayerTestSuite struct {
	t *testing.T
}

func (n *NativeLayerTestSuite) TestMakeLayers() test.Generator {

	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramCompressor, []interface{}{"zstd", "none", "lz4_block"}).
		Dimension(paramFSVersion, []interface{}{"5", "6"}).
		Dimension(paramChunkSize, []interface{}{"0x100000", "0x200000"}).
		Dimension(paramCacheType, []interface{}{"blobcache", ""}).
		Dimension(paramCacheCompressed, []interface{}{true, false}).
		Dimension(paramRafsMode, []interface{}{"direct", "cached"}).
		Dimension(paramEnablePrefetch, []interface{}{false, true}).
		Skip(func(param *tool.DescartesItem) bool {

			// rafs v6 not support cached mode nor dummy cache
			if param.GetString(paramFSVersion) == "6" {
				return param.GetString(paramRafsMode) == "cached" || param.GetString(paramCacheType) == ""
			}

			// dummy cache not support prefetch
			if param.GetString(paramCacheType) == "" && param.GetBool(paramEnablePrefetch) {
				return true
			}

			return false
		})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		ctx := tool.DefaultContext(n.t)
		ctx.Build.Compressor = scenario.GetString(paramCompressor)
		ctx.Build.FSVersion = scenario.GetString(paramFSVersion)
		ctx.Build.ChunkSize = scenario.GetString(paramChunkSize)
		ctx.Runtime.CacheType = scenario.GetString(paramCacheType)
		ctx.Runtime.CacheCompressed = scenario.GetBool(paramCacheCompressed)
		ctx.Runtime.RafsMode = scenario.GetString(paramRafsMode)
		ctx.Runtime.EnablePrefetch = scenario.GetBool(paramEnablePrefetch)

		return scenario.Str(), func(t *testing.T) {
			n.testMakeLayers(*ctx, t)
		}
	}
}

func (n *NativeLayerTestSuite) testMakeLayers(ctx tool.Context, t *testing.T) {

	packOption := converter.PackOption{
		BuilderPath: ctx.Binary.Builder,
		Compressor:  ctx.Build.Compressor,
		FsVersion:   ctx.Build.FSVersion,
		ChunkSize:   ctx.Build.ChunkSize,
	}

	// Prepare work directory
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Make chunk dict layer
	chunkDictLayer := texture.MakeChunkDictLayer(t, filepath.Join(ctx.Env.WorkDir, "source-chunk-dict"))
	chunkDictBlobDigest := chunkDictLayer.Pack(t, packOption, ctx.Env.BlobDir)
	mergeOption := converter.MergeOption{
		ChunkDictPath: "",
		BuilderPath:   ctx.Binary.Builder,
	}
	actualDigests, chunkDictBootstrap := tool.MergeLayers(t, ctx, mergeOption, []converter.Layer{
		{
			Digest: chunkDictBlobDigest,
		},
	})
	require.Equal(t, actualDigests, []digest.Digest{chunkDictBlobDigest})

	// Make lower layer (with chunk dict)
	packOption.ChunkDictPath = chunkDictBootstrap
	lowerLayer := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "source-lower"))
	lowerBlobDigest := lowerLayer.Pack(t, packOption, ctx.Env.BlobDir)

	// Check repeatable build
	lowerBlobDigestNew := lowerLayer.Pack(t, packOption, ctx.Env.BlobDir)
	require.Equal(t, lowerBlobDigest, lowerBlobDigestNew)

	mergeOption = converter.MergeOption{
		ChunkDictPath: chunkDictBootstrap,
		BuilderPath:   ctx.Binary.Builder,
	}
	actualDigests, lowerBootstrap := tool.MergeLayers(t, ctx, mergeOption, []converter.Layer{
		{
			Digest: lowerBlobDigest,
		},
	})
	require.Equal(t, actualDigests, []digest.Digest{chunkDictBlobDigest})

	// Verify lower layer mounted by nydusd
	ctx.Env.BootstrapPath = lowerBootstrap
	tool.Verify(t, ctx, lowerLayer.FileTree)

	// Make upper layer (with chunk dict)
	upperLayer := texture.MakeUpperLayer(t, filepath.Join(ctx.Env.WorkDir, "source-upper"))
	upperBlobDigest := upperLayer.Pack(t, packOption, ctx.Env.BlobDir)

	// Check repeatable build
	upperBlobDigestNew := upperLayer.Pack(t, packOption, ctx.Env.BlobDir)
	require.Equal(t, upperBlobDigest, upperBlobDigestNew)

	mergeOption = converter.MergeOption{
		ChunkDictPath: chunkDictBootstrap,
		BuilderPath:   ctx.Binary.Builder,
	}
	actualDigests, overlayBootstrap := tool.MergeLayers(t, ctx, mergeOption, []converter.Layer{
		{
			Digest: lowerBlobDigest,
		},
		{
			Digest: upperBlobDigest,
		},
	})
	require.Equal(t, actualDigests, []digest.Digest{chunkDictBlobDigest, upperBlobDigest})

	// Verify overlay (lower+upper) layer mounted by nydusd
	lowerLayer.Overlay(t, upperLayer)
	ctx.Env.BootstrapPath = overlayBootstrap
	tool.Verify(t, ctx, lowerLayer.FileTree)
}

func TestNativeLayer(t *testing.T) {
	test.Run(t, &NativeLayerTestSuite{t: t})
}
