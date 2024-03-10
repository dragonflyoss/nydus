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
	paramIteration = "iteration"
)

type ChunkDedupTestSuite struct {
	t *testing.T
}

func (z *ChunkDedupTestSuite) TestChunkDedup() test.Generator {

	scenarios := tool.DescartesIterator{}
	scenarios.Dimension(paramIteration, []interface{}{1, 2})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		ctx := tool.DefaultContext(z.t)
		ctx.Runtime.ChunkDedupDb = ctx.Env.WorkDir + "/cas.db"

		return scenario.Str(), func(t *testing.T) {
			z.testMakeLayers(*ctx, t)
		}
	}
}

func (z *ChunkDedupTestSuite) testMakeLayers(ctx tool.Context, t *testing.T) {

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

func TestChunkDedup(t *testing.T) {
	test.Run(t, &ChunkDedupTestSuite{t: t})
}
