// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type StreamCopyTestSuite struct {
	T              *testing.T
	preparedImages map[string]string
}

func (s *StreamCopyTestSuite) TestStreamCopyFeature() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramImage, []interface{}{"nginx:latest", "alpine:latest"}).
		Dimension("enable_stream_copy", []interface{}{true, false}).
		Dimension("push_chunk_size", []interface{}{"0", "8MB", "16MB", "32MB"})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		ctx := tool.DefaultContext(s.T)
		ctx.Build.FSVersion = "6" // 使用 fs version 6 进行测试

		image := s.prepareImage(s.T, scenario.GetString(paramImage))
		enableStreamCopy := scenario.GetBool("enable_stream_copy")
		pushChunkSize := scenario.GetString("push_chunk_size")

		return scenario.Str(), func(t *testing.T) {
			s.testStreamCopyWithOptions(t, *ctx, image, enableStreamCopy, pushChunkSize)
		}
	}
}

func (s *StreamCopyTestSuite) testStreamCopyWithOptions(t *testing.T, ctx tool.Context, source string, enableStreamCopy bool, pushChunkSize string) {
	// Prepare work directory
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	sourceNydus := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	compressor := "--compressor lz4_block"

	if ctx.Binary.NydusifyOnlySupportV5 {
		fsVersion = ""
		logLevel = ""
	}
	if ctx.Binary.NydusifyNotSupportCompressor {
		compressor = ""
	}

	// Convert source image to nydus format
	convertCmd := fmt.Sprintf(
		"%s %s convert --source %s --target %s %s --nydus-image %s --work-dir %s %s",
		ctx.Binary.Nydusify, logLevel, source, sourceNydus, fsVersion,
		ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
	)
	tool.RunWithoutOutput(t, convertCmd)

	targetCopied := fmt.Sprintf("%s-stream-copied-%s", sourceNydus, uuid.NewString())

	copyCmd := fmt.Sprintf(
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s",
		ctx.Binary.Nydusify, logLevel, sourceNydus, targetCopied, ctx.Binary.Builder,
		filepath.Join(ctx.Env.WorkDir, "copy"),
	)

	if enableStreamCopy {
		copyCmd += " --enable-stream-copy"
	}

	if pushChunkSize != "0" {
		copyCmd += fmt.Sprintf(" --push-chunk-size %s", pushChunkSize)
	}

	t.Logf("Running copy command: %s", copyCmd)
	tool.RunWithoutOutput(t, copyCmd)

	nydusifyPath := ctx.Binary.Nydusify
	if ctx.Binary.NydusifyChecker != "" {
		nydusifyPath = ctx.Binary.NydusifyChecker
	}

	checkCmd := fmt.Sprintf(
		"%s %s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
		nydusifyPath, logLevel, source, targetCopied, ctx.Binary.Builder, ctx.Binary.Nydusd,
		filepath.Join(ctx.Env.WorkDir, "check-copied"),
	)
	tool.RunWithoutOutput(t, checkCmd)

	targetSaved := fmt.Sprintf("file://%s", filepath.Join(ctx.Env.WorkDir, "stream-copied.tar"))
	saveCmd := fmt.Sprintf(
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s",
		ctx.Binary.Nydusify, logLevel, targetCopied, targetSaved, ctx.Binary.Builder,
		filepath.Join(ctx.Env.WorkDir, "save-stream"),
	)

	if enableStreamCopy {
		saveCmd += " --enable-stream-copy"
	}
	if pushChunkSize != "0" {
		saveCmd += fmt.Sprintf(" --push-chunk-size %s", pushChunkSize)
	}

	tool.RunWithoutOutput(t, saveCmd)

	_, err := os.Stat(filepath.Join(ctx.Env.WorkDir, "stream-copied.tar"))
	require.NoError(t, err)

	targetLoaded := fmt.Sprintf("%s-loaded", targetCopied)
	loadCmd := fmt.Sprintf(
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s",
		ctx.Binary.Nydusify, logLevel, targetSaved, targetLoaded, ctx.Binary.Builder,
		filepath.Join(ctx.Env.WorkDir, "load-stream"),
	)

	if enableStreamCopy {
		loadCmd += " --enable-stream-copy"
	}
	if pushChunkSize != "0" {
		loadCmd += fmt.Sprintf(" --push-chunk-size %s", pushChunkSize)
	}

	tool.RunWithoutOutput(t, loadCmd)

	checkLoadedCmd := fmt.Sprintf(
		"%s %s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
		nydusifyPath, logLevel, source, targetLoaded, ctx.Binary.Builder, ctx.Binary.Nydusd,
		filepath.Join(ctx.Env.WorkDir, "check-loaded"),
	)
	tool.RunWithoutOutput(t, checkLoadedCmd)

	t.Logf("Stream copy test completed successfully with enableStreamCopy=%v, pushChunkSize=%s",
		enableStreamCopy, pushChunkSize)
}

func (s *StreamCopyTestSuite) TestStreamCopyPerformance() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramImage, []interface{}{"wordpress:latest"}). // 使用较大的镜像测试性能
		Dimension("test_mode", []interface{}{"stream_vs_normal"})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		ctx := tool.DefaultContext(s.T)
		ctx.Build.FSVersion = "6"

		image := s.prepareImage(s.T, scenario.GetString(paramImage))

		return scenario.Str(), func(t *testing.T) {
			s.testStreamCopyPerformance(t, *ctx, image)
		}
	}
}

func (s *StreamCopyTestSuite) testStreamCopyPerformance(t *testing.T, ctx tool.Context, source string) {
	// Prepare work directory
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	sourceNydus := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	compressor := "--compressor lz4_block"

	if ctx.Binary.NydusifyOnlySupportV5 {
		fsVersion = ""
		logLevel = ""
	}
	if ctx.Binary.NydusifyNotSupportCompressor {
		compressor = ""
	}

	// Convert source image to nydus format
	convertCmd := fmt.Sprintf(
		"%s %s convert --source %s --target %s %s --nydus-image %s --work-dir %s %s",
		ctx.Binary.Nydusify, logLevel, source, sourceNydus, fsVersion,
		ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
	)
	tool.RunWithoutOutput(t, convertCmd)

	targetNormal := fmt.Sprintf("%s-normal-copy-%s", sourceNydus, uuid.NewString())
	normalCopyCmd := fmt.Sprintf(
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s",
		ctx.Binary.Nydusify, logLevel, sourceNydus, targetNormal, ctx.Binary.Builder,
		filepath.Join(ctx.Env.WorkDir, "normal-copy"),
	)

	t.Logf("Testing normal copy mode...")
	tool.RunWithoutOutput(t, normalCopyCmd)

	targetStream := fmt.Sprintf("%s-stream-copy-%s", sourceNydus, uuid.NewString())
	streamCopyCmd := fmt.Sprintf(
		"%s %s copy --source %s --target %s --nydus-image %s --work-dir %s --enable-stream-copy --push-chunk-size 16MB",
		ctx.Binary.Nydusify, logLevel, sourceNydus, targetStream, ctx.Binary.Builder,
		filepath.Join(ctx.Env.WorkDir, "stream-copy"),
	)

	t.Logf("Testing stream copy mode...")
	tool.RunWithoutOutput(t, streamCopyCmd)

	nydusifyPath := ctx.Binary.Nydusify
	if ctx.Binary.NydusifyChecker != "" {
		nydusifyPath = ctx.Binary.NydusifyChecker
	}

	checkNormalCmd := fmt.Sprintf(
		"%s %s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
		nydusifyPath, logLevel, source, targetNormal, ctx.Binary.Builder, ctx.Binary.Nydusd,
		filepath.Join(ctx.Env.WorkDir, "check-normal"),
	)
	tool.RunWithoutOutput(t, checkNormalCmd)

	checkStreamCmd := fmt.Sprintf(
		"%s %s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
		nydusifyPath, logLevel, source, targetStream, ctx.Binary.Builder, ctx.Binary.Nydusd,
		filepath.Join(ctx.Env.WorkDir, "check-stream"),
	)
	tool.RunWithoutOutput(t, checkStreamCmd)

	t.Logf("Performance comparison test completed successfully")
}

func (s *StreamCopyTestSuite) prepareImage(t *testing.T, image string) string {
	if s.preparedImages == nil {
		s.preparedImages = make(map[string]string)
	}

	if cached, exists := s.preparedImages[image]; exists {
		return cached
	}

	prepared := tool.PrepareImage(t, image)
	s.preparedImages[image] = prepared
	return prepared
}

func TestStreamCopy(t *testing.T) {
	test.Run(t, &StreamCopyTestSuite{T: t})
}
