// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package build

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func createFakeBinary(t *testing.T) (string, string, string) {
	t.Helper()

	tempDir := t.TempDir()
	argsPath := filepath.Join(tempDir, "args.txt")
	stdinPath := filepath.Join(tempDir, "stdin.txt")
	binaryPath := filepath.Join(tempDir, "fake-nydus-image.sh")

	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$NYDUS_ARGS_FILE\"\n" +
		"cat > \"$NYDUS_STDIN_FILE\"\n"

	require.NoError(t, os.WriteFile(binaryPath, []byte(script), 0o755))
	t.Setenv("NYDUS_ARGS_FILE", argsPath)
	t.Setenv("NYDUS_STDIN_FILE", stdinPath)

	return binaryPath, argsPath, stdinPath
}

func readLines(t *testing.T, path string) []string {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	text := strings.TrimSpace(string(content))
	if text == "" {
		return nil
	}

	return strings.Split(text, "\n")
}

func TestNewBuilderUsesStdStreams(t *testing.T) {
	builder := NewBuilder("/usr/bin/nydus-image")
	require.Equal(t, "/usr/bin/nydus-image", builder.binaryPath)
	require.Equal(t, os.Stdout, builder.stdout)
	require.Equal(t, os.Stderr, builder.stderr)
}

func TestBuilderRunBuildCommand(t *testing.T) {
	binaryPath, argsPath, stdinPath := createFakeBinary(t)
	builder := NewBuilder(binaryPath)
	builder.stdout = &bytes.Buffer{}
	builder.stderr = &bytes.Buffer{}

	err := builder.Run(BuilderOption{
		ParentBootstrapPath: "/tmp/parent.boot",
		ChunkDict:           "/tmp/chunk.dict",
		BootstrapPath:       "/tmp/bootstrap.boot",
		RootfsPath:          "/tmp/rootfs",
		WhiteoutSpec:        "overlayfs",
		OutputJSONPath:      "/tmp/output.json",
		PrefetchPatterns:    "/etc\n/usr/bin",
		BlobPath:            "/tmp/blob.data",
		AlignedChunk:        true,
		Compressor:          "zstd",
		ChunkSize:           "0x200000",
		FsVersion:           "6",
	})
	require.NoError(t, err)

	require.Equal(t, []string{
		"create",
		"--parent-bootstrap",
		"/tmp/parent.boot",
		"--aligned-chunk",
		"--chunk-dict",
		"/tmp/chunk.dict",
		"--bootstrap",
		"/tmp/bootstrap.boot",
		"--log-level",
		"warn",
		"--whiteout-spec",
		"overlayfs",
		"--output-json",
		"/tmp/output.json",
		"--blob",
		"/tmp/blob.data",
		"--fs-version",
		"6",
		"--compressor",
		"zstd",
		"--prefetch-policy",
		"fs",
		"--chunk-size",
		"0x200000",
		"/tmp/rootfs",
	}, readLines(t, argsPath))

	stdinContent, err := os.ReadFile(stdinPath)
	require.NoError(t, err)
	require.Equal(t, "/etc\n/usr/bin", string(stdinContent))
}

func TestBuilderCompactAndGenerateCommands(t *testing.T) {
	binaryPath, argsPath, stdinPath := createFakeBinary(t)
	builder := NewBuilder(binaryPath)
	builder.stdout = &bytes.Buffer{}
	builder.stderr = &bytes.Buffer{}

	err := builder.Compact(CompactOption{
		ChunkDict:           "/tmp/chunk.dict",
		BootstrapPath:       "/tmp/bootstrap.boot",
		OutputBootstrapPath: "/tmp/output.boot",
		BackendType:         "oss",
		BackendConfigPath:   "/tmp/backend.json",
		OutputJSONPath:      "/tmp/output.json",
		MinUsedRatio:        "30",
		CompactBlobSize:     "1048576",
		MaxCompactSize:      "2097152",
		LayersToCompact:     "2",
		BlobsDir:            "/tmp/blobs",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"compact",
		"--bootstrap",
		"/tmp/bootstrap.boot",
		"--blob-dir",
		"/tmp/blobs",
		"--min-used-ratio",
		"30",
		"--compact-blob-size",
		"1048576",
		"--max-compact-size",
		"2097152",
		"--layers-to-compact",
		"2",
		"--backend-type",
		"oss",
		"--backend-config-file",
		"/tmp/backend.json",
		"--log-level",
		"info",
		"--output-json",
		"/tmp/output.json",
		"--output-bootstrap",
		"/tmp/output.boot",
		"--chunk-dict",
		"/tmp/chunk.dict",
	}, readLines(t, argsPath))
	require.Empty(t, readLines(t, stdinPath))

	err = builder.Generate(GenerateOption{
		BootstrapPaths:         []string{"/tmp/layer1.boot", "/tmp/layer2.boot"},
		DatabasePath:           "/tmp/chunk.db",
		ChunkdictBootstrapPath: "/tmp/chunkdict.boot",
		OutputPath:             "/tmp/chunkdict.json",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"chunkdict",
		"generate",
		"--log-level",
		"warn",
		"--bootstrap",
		"/tmp/chunkdict.boot",
		"--database",
		"/tmp/chunk.db",
		"--output-json",
		"/tmp/chunkdict.json",
		"/tmp/layer1.boot",
		"/tmp/layer2.boot",
	}, readLines(t, argsPath))
}
