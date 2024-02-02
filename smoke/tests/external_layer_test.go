// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/containerd/nydus-snapshotter/pkg/external"
	"github.com/containerd/nydus-snapshotter/pkg/external/backend/local"
	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type ExternalLayerTestSuite struct {
	t *testing.T
}

func (n *ExternalLayerTestSuite) TestMakeLayers() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramCompressor, []interface{}{"zstd"}).
		Dimension(paramFSVersion, []interface{}{"6"}).
		Skip(func(param *tool.DescartesItem) bool {
			return false
		})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		ctx := tool.DefaultContext(n.t)

		return scenario.Str(), func(t *testing.T) {
			n.testMakeLayers(*ctx, t)
		}
	}
}

func (n *ExternalLayerTestSuite) testMakeLayers(ctx tool.Context, t *testing.T) {
	// Prepare work directory
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Make lower layer
	lowerLayerSourceDir := filepath.Join(ctx.Env.WorkDir, "source-lower")
	lowerLayer := texture.MakeLowerLayer(t, lowerLayerSourceDir)

	// Prepare .nydusattributes file
	attributesPath := filepath.Join(ctx.Env.WorkDir, ".nydusattributes")
	backendMetaPath := filepath.Join(ctx.Env.CacheDir, ".backend.meta")
	backendConfigPath := filepath.Join(ctx.Env.CacheDir, ".backend.json")
	err := external.Handle(context.Background(), external.Options{
		Dir:              lowerLayerSourceDir,
		Handler:          local.NewHandler(lowerLayerSourceDir),
		MetaOutput:       backendMetaPath,
		BackendOutput:    backendConfigPath,
		AttributesOutput: attributesPath,
	})
	require.NoError(t, err)

	// Build lower layer
	packOption := converter.PackOption{
		BuilderPath:    ctx.Binary.Builder,
		Compressor:     ctx.Build.Compressor,
		FsVersion:      ctx.Build.FSVersion,
		ChunkSize:      ctx.Build.ChunkSize,
		AttributesPath: attributesPath,
	}
	lowerBlobDigest, lowerExternalBlobDigest := lowerLayer.PackWithAttributes(t, packOption, ctx.Env.BlobDir, lowerLayerSourceDir)

	err = os.Rename(backendMetaPath, filepath.Join(ctx.Env.CacheDir, lowerExternalBlobDigest.Hex()+".backend.meta"))
	require.NoError(t, err)

	err = os.Rename(backendConfigPath, filepath.Join(ctx.Env.CacheDir, lowerExternalBlobDigest.Hex()+".backend.json"))
	require.NoError(t, err)

	// Make upper layer
	upperLayer := texture.MakeUpperLayer(t, filepath.Join(ctx.Env.WorkDir, "source-upper"))
	upperBlobDigest := upperLayer.Pack(t, packOption, ctx.Env.BlobDir)

	mergeOption := converter.MergeOption{
		BuilderPath: ctx.Binary.Builder,
	}
	actualDigests, mergedBootstrap := tool.MergeLayers(t, ctx, mergeOption, []converter.Layer{
		{
			Digest: lowerBlobDigest,
		},
		{
			Digest: lowerExternalBlobDigest,
		},
		{
			Digest: upperBlobDigest,
		},
	})
	require.Equal(t, actualDigests, []digest.Digest{lowerBlobDigest, lowerExternalBlobDigest, upperBlobDigest})

	// Verify lower layer mounted by nydusd
	lowerLayer.Overlay(t, upperLayer)
	ctx.Env.BootstrapPath = mergedBootstrap
	tool.Verify(t, ctx, lowerLayer.FileTree)
}

func TestExternalLayer(t *testing.T) {
	test.Run(t, &ExternalLayerTestSuite{t: t})
}
