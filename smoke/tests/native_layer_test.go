// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/image-service/smoke/tests/texture"
	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func makeNativeLayerTest(ctx tool.Context) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

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
}

func testNativeLayer(t *testing.T, ctx tool.Context) {
	t.Parallel()

	compressors := []string{"zstd", "none", "lz4_block"}
	fsVersions := []string{"5", "6"}
	// FIXME: specify chunk size `0x200000` case.
	chunkSizes := []string{"0x100000"}

	cacheTypes := []string{"blobcache", ""}
	cacheCompresses := []bool{true, false}
	rafsModes := []string{"direct", "cached"}
	enablePrefetches := []bool{false, true}

	for _, compressor := range compressors {
		for _, fsVersion := range fsVersions {
			for _, chunkSize := range chunkSizes {
				for _, cacheType := range cacheTypes {
					for _, cacheCompressed := range cacheCompresses {
						for _, rafsMode := range rafsModes {
							for _, enablePrefetch := range enablePrefetches {
								if fsVersion == "6" {
									if rafsMode == "cached" || cacheType == "" {
										continue
									}
								}
								if cacheType == "" && enablePrefetch {
									continue
								}

								ctx.Build.Compressor = compressor
								ctx.Build.FSVersion = fsVersion
								ctx.Build.ChunkSize = chunkSize
								ctx.Runtime.CacheType = cacheType
								ctx.Runtime.CacheCompressed = cacheCompressed
								ctx.Runtime.RafsMode = rafsMode
								ctx.Runtime.EnablePrefetch = enablePrefetch

								name := fmt.Sprintf(
									"compressor=%s,fs_version=%s,chunk_size=%s,cache_type=%s,cache_compressed=%v,rafs_mode=%s,enable_prefetch=%v",
									compressor, fsVersion, chunkSize, cacheType, cacheCompressed, rafsMode, enablePrefetch,
								)
								t.Run(name, makeNativeLayerTest(ctx))
							}
						}
					}
				}
			}
		}
	}
}

func TestNativeLayer(t *testing.T) {
	testNativeLayer(t, *tool.DefaultContext())
}
