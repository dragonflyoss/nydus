// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
)

const (
	paramIteration = "iteration"
)

type ChunkDedupTestSuite struct{}

func (c *ChunkDedupTestSuite) TestChunkDedup() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.Dimension(paramIteration, []interface{}{1})

	file, err := os.CreateTemp("", "cas-*.db")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file.Name())

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		return scenario.Str(), func(t *testing.T) {
			c.testRemoteWithDedup(t, file.Name())
		}
	}
}

func (c *ChunkDedupTestSuite) testRemoteWithDedup(t *testing.T, dbPath string) {
	ctx, layer := texture.PrepareLayerWithContext(t)
	defer ctx.Destroy(t)
	ctx.Runtime.EnablePrefetch = false
	ctx.Runtime.ChunkDedupDb = dbPath

	nydusd, err := tool.NewNydusdWithContext(*ctx)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)
	defer nydusd.Umount()
	nydusd.Verify(t, layer.FileTree)
	metrics, err := nydusd.GetBackendMetrics()
	require.NoError(t, err)
	require.Zero(t, metrics.ReadErrors)

	ctx2, layer2 := texture.PrepareLayerWithContext(t)
	defer ctx2.Destroy(t)
	ctx2.Runtime.EnablePrefetch = false
	ctx2.Runtime.ChunkDedupDb = dbPath

	nydusd2, err := tool.NewNydusdWithContext(*ctx2)
	require.NoError(t, err)
	err = nydusd2.Mount()
	require.NoError(t, err)
	defer nydusd2.Umount()
	nydusd2.Verify(t, layer2.FileTree)
	metrics2, err := nydusd2.GetBackendMetrics()
	require.NoError(t, err)
	require.Zero(t, metrics2.ReadErrors)

	require.Greater(t, metrics.ReadCount, metrics2.ReadCount)
	require.Greater(t, metrics.ReadAmountTotal, metrics2.ReadAmountTotal)
}

func TestChunkDedup(t *testing.T) {
	test.Run(t, &ChunkDedupTestSuite{})
}
