// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
)

const (
	paramZran      = "zran"
	paramBatch     = "batch"
	paramEncrypt   = "encrypt"
	paramAmplifyIO = "amplify_io"
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
		Dimension(paramEncrypt, []interface{}{false, true}).
		Skip(
			func(param *tool.DescartesItem) bool {
				// Zran and Batch not work with rafs v5.
				if param.GetString(paramFSVersion) == "5" && (param.GetBool(paramZran)) ||
					param.GetString(paramBatch) != "0" || (param.GetBool(paramEncrypt)) {
					return true
				}

				// Zran and Batch can not work together.
				// Zran and Encrpt can not work together.
				return (param.GetBool(paramZran) && param.GetString(paramBatch) != "0") ||
					(param.GetBool(paramZran) && param.GetBool(paramEncrypt))
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
		ctx.Build.Encrypt = scenario.GetBool(paramEncrypt)

		image := i.prepareImage(i.T, scenario.GetString(paramImage))
		return scenario.Str(), func(t *testing.T) {
			i.TestConvertAndCopyImage(t, *ctx, image, true)
		}
	}
}

func (i *ImageTestSuite) TestConvertAndCopyImage(t *testing.T, ctx tool.Context, source string, testCopy bool) {

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

	enableEncrypt := ""
	if ctx.Build.Encrypt {
		enableEncrypt = "--encrypt"
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
		"%s %s convert --source %s --target %s %s %s %s %s --nydus-image %s --work-dir %s %s",
		ctx.Binary.Nydusify, logLevel, source, target, fsVersion, enableOCIRef, enableBatchSize, enableEncrypt, ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
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

	if !testCopy {
		return
	}

	// Copy image
	targetCopied := fmt.Sprintf("%s_copied", target)
	copyCmd := fmt.Sprintf(
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s --push-chunk-size 1MB",
		ctx.Binary.Nydusify, logLevel, target, targetCopied, ctx.Binary.Builder, ctx.Env.WorkDir,
	)
	tool.RunWithoutOutput(t, copyCmd)

	// Check copied image
	checkCmd = fmt.Sprintf(
		"%s %s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
		nydusifyPath, logLevel, source, targetCopied, ctx.Binary.Builder, ctx.Binary.Nydusd, filepath.Join(ctx.Env.WorkDir, "check"),
	)
	tool.RunWithoutOutput(t, checkCmd)
}

func (i *ImageTestSuite) TestGenerateChunkdict() test.Generator {
	return func() (name string, testCase test.Case) {
		imagename1 := "redis:7.0.1"
		imagename2 := "redis:7.0.2"
		imagename3 := "redis:7.0.3"
		image1 := i.prepareImage(i.T, imagename1)
		image2 := i.prepareImage(i.T, imagename2)
		image3 := i.prepareImage(i.T, imagename3)
		ctx := tool.DefaultContext(i.T)

		// Prepare work directory
		ctx.PrepareWorkDir(i.T)
		defer ctx.Destroy(i.T)

		logLevel := "--log-level warn"
		nydusifyPath := ctx.Binary.Nydusify

		// Test v6
		target1v6 := fmt.Sprintf("%s-nydus-%s", image1, uuid.NewString())
		target2v6 := fmt.Sprintf("%s-nydus-%s", image2, uuid.NewString())
		target3v6 := fmt.Sprintf("%s-nydus-%s", image3, uuid.NewString())
		convertCmd1 := fmt.Sprintf(
			"%s %s convert --source %s --target %s --nydus-image %s --work-dir %s",
			ctx.Binary.Nydusify, logLevel, image1, target1v6, ctx.Binary.Builder, ctx.Env.TempDir,
		)
		tool.RunWithoutOutput(i.T, convertCmd1)
		convertCmd2 := fmt.Sprintf(
			"%s %s convert --source %s --target %s --nydus-image %s --work-dir %s",
			ctx.Binary.Nydusify, logLevel, image2, target2v6, ctx.Binary.Builder, ctx.Env.TempDir,
		)
		tool.RunWithoutOutput(i.T, convertCmd2)
		convertCmd3 := fmt.Sprintf(
			"%s %s convert --source %s --target %s --nydus-image %s --work-dir %s",
			ctx.Binary.Nydusify, logLevel, image3, target3v6, ctx.Binary.Builder, ctx.Env.TempDir,
		)
		tool.RunWithoutOutput(i.T, convertCmd3)

		backendtype := "--backend-type oss"
		sourceinsecure := "--source-insecure"
		targetinsecure := "--target-insecure"

		jsonData := `{
			"endpoint": "oss-cn-zhangjiakou.aliyuncs.com",
			"access_key_id": "LTAI5tKHuSQQXVjSE7PgKYhf",
			"access_key_secret": "FBYp1JDxlIZt8cCpFWpq3j9HYokw8a",
			"bucket_name": "testcompact1"
		}`

		formattedData, err := json.MarshalIndent(json.RawMessage(jsonData), "", "  ")
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			return
		}
		os.WriteFile("output.json", formattedData, 0644)

		backendconfigfile := "--backend-config-file output.json"

		targetv6 := fmt.Sprintf("%s,%s,%s", target1v6, target2v6, target3v6)
		chunkdictv6 := fmt.Sprintf("%s-nydus-%s", image1, uuid.NewString())

		generateCmd := fmt.Sprintf(
			"%s %s chunkdict generate --sources %s --target %s %s %s %s %s --nydus-image %s --work-dir %s",
			nydusifyPath, logLevel, targetv6, chunkdictv6, sourceinsecure, targetinsecure, backendtype, backendconfigfile, ctx.Binary.Builder, filepath.Join(ctx.Env.WorkDir, "generate"),
		)
		tool.RunWithoutOutput(i.T, generateCmd)

		checkCmd := fmt.Sprintf(
			"%s %s check  --target %s --nydus-image %s --nydusd %s --work-dir %s",
			nydusifyPath, logLevel, chunkdictv6, ctx.Binary.Builder, ctx.Binary.Nydusd, filepath.Join(ctx.Env.WorkDir, "check"),
		)
		tool.RunWithoutOutput(i.T, checkCmd)

		// Test v5
		fsversion := "--fs-version 5"
		target1v5 := fmt.Sprintf("%s-nydus5-%s", image1, uuid.NewString())
		target2v5 := fmt.Sprintf("%s-nydus5-%s", image2, uuid.NewString())
		target3v5 := fmt.Sprintf("%s-nydus5-%s", image3, uuid.NewString())
		convertCmd4 := fmt.Sprintf(
			"%s %s convert --source %s --target %s --nydus-image %s %s --work-dir %s",
			ctx.Binary.Nydusify, logLevel, image1, target1v5, ctx.Binary.Builder, fsversion, ctx.Env.TempDir,
		)
		tool.RunWithoutOutput(i.T, convertCmd4)
		convertCmd5 := fmt.Sprintf(
			"%s %s convert --source %s --target %s --nydus-image %s %s --work-dir %s",
			ctx.Binary.Nydusify, logLevel, image2, target2v5, ctx.Binary.Builder, fsversion, ctx.Env.TempDir,
		)
		tool.RunWithoutOutput(i.T, convertCmd5)
		convertCmd6 := fmt.Sprintf(
			"%s %s convert --source %s --target %s --nydus-image %s %s --work-dir %s",
			ctx.Binary.Nydusify, logLevel, image3, target3v5, ctx.Binary.Builder, fsversion, ctx.Env.TempDir,
		)
		tool.RunWithoutOutput(i.T, convertCmd6)

		targetv5 := fmt.Sprintf("%s,%s,%s", target1v5, target2v5, target3v5)
		chunkdictv5 := fmt.Sprintf("%s-nydus5-%s", image1, uuid.NewString())

		generateCmd2 := fmt.Sprintf(
			"%s %s chunkdict generate --sources %s --target %s %s %s %s %s --nydus-image %s --work-dir %s",
			nydusifyPath, logLevel, targetv5, chunkdictv5, sourceinsecure, targetinsecure, backendtype, backendconfigfile, ctx.Binary.Builder, filepath.Join(ctx.Env.WorkDir, "generate"),
		)
		tool.RunWithoutOutput(i.T, generateCmd2)

		return "generateChunkdict", nil
	}
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
