// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
)

const (
	paramIteration = "iteration"
)

type ChunkDedupTestSuite struct{}

type BackendMetrics struct {
	ReadCount       uint64 `json:"read_count"`
	ReadAmountTotal uint64 `json:"read_amount_total"`
	ReadErrors      uint64 `json:"read_errors"`
}

func (c *ChunkDedupTestSuite) TestChunkDedup() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.Dimension(paramIteration, []interface{}{1})

	file, _ := os.CreateTemp("", "cas-*.db")
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
	metrics := c.getBackendMetrics(t, filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"))
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
	metrics2 := c.getBackendMetrics(t, filepath.Join(ctx2.Env.WorkDir, "nydusd-api.sock"))
	require.Zero(t, metrics2.ReadErrors)

	require.Greater(t, metrics.ReadCount, metrics2.ReadCount)
	require.Greater(t, metrics.ReadAmountTotal, metrics2.ReadAmountTotal)
}

func (c *ChunkDedupTestSuite) getBackendMetrics(t *testing.T, sockPath string) *BackendMetrics {
	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", sockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get("http://unix/api/v1/metrics/backend")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var metrics BackendMetrics
	if err = json.Unmarshal(body, &metrics); err != nil {
		require.NoError(t, err)
	}

	return &metrics
}

func TestChunkDedup(t *testing.T) {
	test.Run(t, &ChunkDedupTestSuite{})
}
