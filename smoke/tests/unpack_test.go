// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
)

type UnpackTestSuite struct{}

func (u *UnpackTestSuite) TestUnpack() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramCompressor, []interface{}{"none", "zstd"}).
		Dimension(paramBatch, []interface{}{"0", "0x100000"}).
		Dimension(paramEncrypt, []interface{}{false, true})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		return scenario.Str(), func(t *testing.T) {
			ctx := tool.DefaultContext(t)
			ctx.Build.Compressor = scenario.GetString(paramCompressor)
			ctx.Build.BatchSize = scenario.GetString(paramBatch)
			ctx.Build.Encrypt = scenario.GetBool(paramEncrypt)
			u.testUnpack(t, ctx)
		}
	}
}

func (u *UnpackTestSuite) testUnpack(t *testing.T, ctx *tool.Context) {
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Small files are merged into batch chunks, the large one is split into normal chunks.
	sourceDir := filepath.Join(ctx.Env.WorkDir, "source")
	layer := tool.NewLayer(t, sourceDir)
	layer.CreateDir(t, "dir")
	for i := 0; i < 20; i++ {
		data := bytes.Repeat([]byte{byte('a' + i)}, 100*(i+1))
		layer.CreateFile(t, fmt.Sprintf("dir/file-%d", i), data)
	}
	layer.CreateFile(t, "empty", nil)
	layer.CreateLargeFile(t, "large", 3)

	options := ""
	if ctx.Build.BatchSize != "0" {
		options += " --batch-size " + ctx.Build.BatchSize
	}
	if ctx.Build.Encrypt {
		options += " --encrypt"
	}
	ctx.Env.BootstrapPath = filepath.Join(ctx.Env.WorkDir, "bootstrap")
	tool.Run(t, fmt.Sprintf("%s create -t dir-rafs --fs-version %s --chunk-size %s --compressor %s%s --blob-dir %s --bootstrap %s %s",
		ctx.Binary.Builder, ctx.Build.FSVersion, ctx.Build.ChunkSize, ctx.Build.Compressor, options,
		ctx.Env.BlobDir, ctx.Env.BootstrapPath, sourceDir))

	tarPath := filepath.Join(ctx.Env.WorkDir, "unpacked.tar")
	unpackDir := filepath.Join(ctx.Env.WorkDir, "unpacked")
	require.NoError(t, os.MkdirAll(unpackDir, 0755))
	tool.Run(t, fmt.Sprintf("%s unpack --blob-dir %s --output %s %s",
		ctx.Binary.Builder, ctx.Env.BlobDir, tarPath, ctx.Env.BootstrapPath))
	tool.Run(t, fmt.Sprintf("tar -xf %s -C %s", tarPath, unpackDir))
	tool.Run(t, fmt.Sprintf("diff -r %s %s", sourceDir, unpackDir))
}

func TestUnpack(t *testing.T) {
	test.Run(t, &UnpackTestSuite{})
}
