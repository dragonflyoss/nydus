// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
)

type CasTestSuite struct{}

func (c *CasTestSuite) TestCasTables() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.Dimension(paramEnablePrefetch, []interface{}{false, true})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		return scenario.Str(), func(t *testing.T) {
			c.testCasTables(t, scenario.GetBool(paramEnablePrefetch))
		}
	}
}

func (c *CasTestSuite) testCasTables(t *testing.T, enablePrefetch bool) {
	ctx, layer := texture.PrepareLayerWithContext(t)
	ctx.Runtime.EnablePrefetch = enablePrefetch
	ctx.Runtime.ChunkDedupDb = filepath.Join(ctx.Env.WorkDir, "cas.db")

	nydusd, err := tool.NewNydusdWithContext(*ctx)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)
	defer nydusd.Umount()
	nydusd.Verify(t, layer.FileTree)

	db, err := sql.Open("sqlite3", ctx.Runtime.ChunkDedupDb)
	require.NoError(t, err)
	defer db.Close()

	for _, expectedTable := range []string{"Blobs", "Chunks"} {
		// Manual execution WAL Checkpoint
		_, err = db.Exec("PRAGMA wal_checkpoint(FULL)")
		require.NoError(t, err)
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s;", expectedTable)
		err = db.QueryRow(query).Scan(&count)
		require.NoError(t, err)
		if expectedTable == "Blobs" {
			require.Equal(t, 1, count)
		} else {
			rows, err := db.Query(fmt.Sprintf("SELECT * FROM %s;", expectedTable))
			require.NoError(t, err)
			defer rows.Close()
			// 获取列名
			columns, err := rows.Columns()
			require.NoError(t, err)
			t.Logf("Columns: %v", columns)
			for rows.Next() {
				values := make([]interface{}, len(columns))
				valuePtrs := make([]interface{}, len(columns))
				for i := range columns {
					valuePtrs[i] = &values[i]
				}
				err := rows.Scan(valuePtrs...)
				require.NoError(t, err)

				rowData := make([]interface{}, len(columns))
				for i := range columns {
					val := values[i]
					b, ok := val.([]byte)
					if ok {
						rowData[i] = string(b)
					} else {
						rowData[i] = val
					}
				}
				t.Logf("Row: %v", rowData)
			}
			require.Equal(t, 13, count)
		}
	}
}

func (c *CasTestSuite) TestCasGcUmountByAPI() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.Dimension(paramEnablePrefetch, []interface{}{false, true})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		return scenario.Str(), func(t *testing.T) {
			c.testCasGcUmountByAPI(t, scenario.GetBool(paramEnablePrefetch))
		}
	}
}

func (c *CasTestSuite) testCasGcUmountByAPI(t *testing.T, enablePrefetch bool) {
	ctx, layer := texture.PrepareLayerWithContext(t)
	defer ctx.Destroy(t)

	config := tool.NydusdConfig{
		NydusdPath:   ctx.Binary.Nydusd,
		MountPath:    ctx.Env.MountDir,
		APISockPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:   filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		ChunkDedupDb: filepath.Join(ctx.Env.WorkDir, "cas.db"),
	}
	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)

	err = nydusd.Mount()
	defer nydusd.Umount()
	require.NoError(t, err)

	config.BootstrapPath = ctx.Env.BootstrapPath
	config.MountPath = "/mount"
	config.BackendType = "localfs"
	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
	config.BlobCacheDir = ctx.Env.CacheDir
	config.CacheType = ctx.Runtime.CacheType
	config.CacheCompressed = ctx.Runtime.CacheCompressed
	config.RafsMode = ctx.Runtime.RafsMode
	config.EnablePrefetch = enablePrefetch
	config.DigestValidate = false
	config.AmplifyIO = ctx.Runtime.AmplifyIO
	err = nydusd.MountByAPI(config)
	require.NoError(t, err)

	nydusd.VerifyByPath(t, layer.FileTree, config.MountPath)

	db, err := sql.Open("sqlite3", config.ChunkDedupDb)
	require.NoError(t, err)
	defer db.Close()

	for _, expectedTable := range []string{"Blobs", "Chunks"} {
		_, err = db.Exec("PRAGMA wal_checkpoint(FULL)")
		require.NoError(t, err)
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s;", expectedTable)
		err := db.QueryRow(query).Scan(&count)
		require.NoError(t, err)
		require.NotZero(t, count)
	}

	// Mock nydus snapshotter clear cache
	os.RemoveAll(filepath.Join(ctx.Env.WorkDir, "cache"))
	time.Sleep(1 * time.Second)

	nydusd.UmountByAPI(config.MountPath)

	for _, expectedTable := range []string{"Blobs", "Chunks"} {
		_, err = db.Exec("PRAGMA wal_checkpoint(FULL)")
		require.NoError(t, err)
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s;", expectedTable)
		err := db.QueryRow(query).Scan(&count)
		require.NoError(t, err)
		require.Zero(t, count)
	}
}

func TestCas(t *testing.T) {
	test.Run(t, &CasTestSuite{})
}
