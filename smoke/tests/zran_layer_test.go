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
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

const (
	paramGzip = "gzip"
)

func makeZranLayerTest(ctx tool.Context) func(t *testing.T) {
	return func(t *testing.T) {
		// Prepare work directory
		ctx.PrepareWorkDir(t)
		defer ctx.Destroy(t)

		lowerLayer := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "source"))
		lowerOCIBlobDigest, lowerRafsBlobDigest := lowerLayer.PackRef(t, ctx, ctx.Env.BlobDir, ctx.Build.OCIRefGzip)
		mergeOption := converter.MergeOption{
			BuilderPath:   ctx.Binary.Builder,
			ChunkDictPath: "",
			OCIRef:        true,
		}
		actualDigests, lowerBootstrap := tool.MergeLayers(t, ctx, mergeOption, []converter.Layer{
			{
				Digest:         lowerRafsBlobDigest,
				OriginalDigest: &lowerOCIBlobDigest,
			},
		})
		require.Equal(t, []digest.Digest{lowerOCIBlobDigest}, actualDigests)

		// Verify lower layer mounted by nydusd
		ctx.Env.BootstrapPath = lowerBootstrap
		tool.Verify(t, ctx, lowerLayer.FileTree)
	}
}

func TestZranLayer(t *testing.T) {
	t.Parallel()

	params := tool.DescartesIterator{}
	params.
		Register(paramGzip, []interface{}{false, true}).
		Register(paramCacheCompressed, []interface{}{true, false}).
		Register(paramEnablePrefetch, []interface{}{false, true})

	ctx := tool.DefaultContext()
	for params.HasNext() {
		param := params.Next()

		ctx.Build.OCIRefGzip = param.GetBool(paramGzip)
		ctx.Runtime.CacheCompressed = param.GetBool(paramCacheCompressed)
		ctx.Runtime.EnablePrefetch = param.GetBool(paramEnablePrefetch)
		t.Run(param.Str(), makeZranLayerTest(*ctx))
	}
}
