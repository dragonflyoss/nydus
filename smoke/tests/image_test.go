// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/google/uuid"
)

const (
	paramZran  = "zran"
	paramBatch = "batch"
)

type ImageTestSuite struct {
	T              *testing.T
	preparedImages map[string]string
}

func (i *ImageTestSuite) TestConvertImages() test.Generator {

	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramImage, []interface{}{"nginx:latest"}).
		Dimension(paramFSVersion, []interface{}{"5", "6"}).
		Dimension(paramZran, []interface{}{false, true}).
		Dimension(paramBatch, []interface{}{"0", "0x100000"}).
		Skip(
			func(param *tool.DescartesItem) bool {
				// Zran and Batch not work with rafs v5.
				if param.GetString(paramFSVersion) == "5" && (param.GetBool(paramZran) || param.GetString(paramBatch) != "0") {
					return true
				}

				// Zran and Batch can not work together.
				return param.GetBool(paramZran) && param.GetString(paramBatch) != "0"
			})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		ctx := tool.DefaultContext(i.T)
		ctx.Build.FSVersion = scenario.GetString(paramFSVersion)
		ctx.Build.OCIRef = scenario.GetBool(paramZran)
		ctx.Build.BatchSize = scenario.GetString(paramBatch)

		image := i.prepareImage(i.T, scenario.GetString(paramImage))
		return scenario.Str(), func(t *testing.T) {
			i.TestConvertImage(t, *ctx, image)
		}
	}
}

func (i *ImageTestSuite) TestConvertImage(t *testing.T, ctx tool.Context, source string) {

	// Prepare work directory
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Prepare options
	enableOCIRef := ""
	if ctx.Build.OCIRef {
		enableOCIRef = "--oci-ref"
	}

	enableBatchSize := ""
	if ctx.Build.BatchSize != "0" {
		enableBatchSize = "--batch-size " + ctx.Build.BatchSize
	}

	target := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	if ctx.Binary.NydusifyOnlySupportV5 {
		fsVersion = ""
		logLevel = ""
	}
	compressor := "--compressor lz4_block"
	if ctx.Binary.NydusifyNotSupportCompressor {
		compressor = ""
	}

	// Convert image
	convertCmd := fmt.Sprintf(
		"%s %s convert --source %s --target %s %s %s %s --nydus-image %s --work-dir %s %s",
		ctx.Binary.Nydusify, logLevel, source, target, fsVersion, enableOCIRef, enableBatchSize, ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
	)
	tool.RunWithoutOutput(t, convertCmd)

	// Check image
	nydusifyPath := ctx.Binary.Nydusify
	if ctx.Binary.NydusifyChecker != "" {
		nydusifyPath = ctx.Binary.NydusifyChecker
	}
	checkCmd := fmt.Sprintf(
		"%s %s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
		nydusifyPath, logLevel, source, target, ctx.Binary.Builder, ctx.Binary.Nydusd, filepath.Join(ctx.Env.WorkDir, "check"),
	)
	tool.RunWithoutOutput(t, checkCmd)
}

func (i *ImageTestSuite) prepareImage(t *testing.T, image string) string {
	if i.preparedImages == nil {
		i.preparedImages = make(map[string]string)
	}
	loc, ok := i.preparedImages[image]
	if !ok {
		loc = tool.PrepareImage(t, image)
		i.preparedImages[image] = loc
	}
	return loc
}

func TestImage(t *testing.T) {
	test.Run(t, &ImageTestSuite{T: t})
}
