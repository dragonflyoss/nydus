// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"path/filepath"
	"strings"
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
		// "%s %s copy --source %s --target %s --nydus-image %s --work-dir %s --push-chunk-size 1MB",
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s",
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

func (i *ImageTestSuite) TestGenerateChunkdicts() test.Generator {
	images := []string{"redis:7.0.1", "redis:7.0.2", "redis:7.0.3"}
	var sources []string
	for _, image := range images {
		image = i.prepareImage(i.T, image)
		sources = append(sources, image)
	}
	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramFSVersion, []interface{}{"5", "6"})
	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()
		ctx := tool.DefaultContext(i.T)
		ctx.Build.FSVersion = scenario.GetString(paramFSVersion)
		return "chunkdict:" + scenario.Str(), func(t *testing.T) {
			i.TestChundict(t, *ctx, sources)
		}
	}
}

func (i *ImageTestSuite) TestChundict(t *testing.T, ctx tool.Context, images []string) {
	trainImage := images[:len(images)-1]
	testImage := images[len(images)-1]

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Prepare options.
	enableOCIRef := ""
	enableEncrypt := ""
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	compressor := "--compressor lz4_block"

	// Prepare nydus images.
	var targets []string
	for _, image := range trainImage {
		target := fmt.Sprintf("%s-nydus-%s", image, uuid.NewString())
		targets = append(targets, target)

		fmt.Println("target:", target)
		convertCmd := fmt.Sprintf(
			"%s %s convert --source %s --target %s %s %s %s %s --nydus-image %s --work-dir %s %s",
			ctx.Binary.Nydusify, logLevel, image, target, fsVersion, enableOCIRef, "", enableEncrypt, ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
		)
		tool.RunWithoutOutput(t, convertCmd)
	}
	targetsStr := strings.Join(targets, ",")

	// Generate chunkdict.
	chunkdict := fmt.Sprintf("%s/redis:nydus-chunkdict-%s", strings.SplitN(testImage, "/", 2)[0], uuid.NewString())
	fmt.Println("chunkdict:", chunkdict)
	generateCmd := fmt.Sprintf(
		"%s %s chunkdict generate --sources %s --target %s --source-insecure --target-insecure --nydus-image %s --work-dir %s",
		ctx.Binary.Nydusify, logLevel, targetsStr, chunkdict, ctx.Binary.Builder, filepath.Join(ctx.Env.WorkDir, "generate"),
	)
	tool.RunWithoutOutput(t, generateCmd)
	fmt.Println("generateCmd:", generateCmd)

	// Covert test image by chunkdict.
	target := fmt.Sprintf("%s-nydus-%s", testImage, uuid.NewString())
	convertCmd := fmt.Sprintf(
		"%s %s convert --source %s --target %s %s %s %s %s --nydus-image %s --work-dir %s %s",
		ctx.Binary.Nydusify, logLevel, testImage, target, fsVersion, enableOCIRef, "", enableEncrypt, ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
	)
	tool.RunWithoutOutput(t, convertCmd)

	// Check nydus image covert by chunkdict.
	checkCmd := fmt.Sprintf(
		"%s %s check --target %s --nydus-image %s --nydusd %s --work-dir %s",
		ctx.Binary.Nydusify, logLevel, target, ctx.Binary.Builder, ctx.Binary.Nydusd, filepath.Join(ctx.Env.WorkDir, "check"),
	)
	tool.RunWithoutOutput(t, checkCmd)
	fmt.Println("checkCmd:", checkCmd)
	ctx.Destroy(t)
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
