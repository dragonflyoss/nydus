// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package optimizer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func createOptimizerBinary(t *testing.T, script string) (string, string) {
	t.Helper()

	tempDir := t.TempDir()
	argsPath := filepath.Join(tempDir, "args.txt")
	binaryPath := filepath.Join(tempDir, "fake-optimizer.sh")
	require.NoError(t, os.WriteFile(binaryPath, []byte(script), 0o755))
	t.Setenv("OPTIMIZER_ARGS_FILE", argsPath)

	return binaryPath, argsPath
}

func readOptimizerArgs(t *testing.T, path string) []string {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestMakeDesc(t *testing.T) {
	oldDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Annotations: map[string]string{"k": "v"}}
	data, newDesc, err := makeDesc(map[string]string{"hello": "world"}, oldDesc)
	require.NoError(t, err)
	require.NotNil(t, newDesc)
	require.Equal(t, int64(len(data)), newDesc.Size)
	require.Equal(t, oldDesc.MediaType, newDesc.MediaType)
	require.Equal(t, oldDesc.Annotations["k"], newDesc.Annotations["k"])
	require.Equal(t, digest.SHA256.FromBytes(data), newDesc.Digest)

	data, newDesc, err = makeDesc(map[string]interface{}{"bad": make(chan int)}, oldDesc)
	require.Nil(t, data)
	require.Nil(t, newDesc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "json marshal")
}

func TestPackToTar(t *testing.T) {
	files := []File{{Name: EntryBootstrap, Reader: bytes.NewBufferString("bootstrap"), Size: int64(len("bootstrap"))}}
	reader := packToTar(files, true)
	defer reader.Close()

	gz, err := gzip.NewReader(reader)
	require.NoError(t, err)
	defer gz.Close()
	tw := tar.NewReader(gz)

	hdr, err := tw.Next()
	require.NoError(t, err)
	require.Equal(t, "image", hdr.Name)

	hdr, err = tw.Next()
	require.NoError(t, err)
	require.Equal(t, filepath.Join("image", EntryBootstrap), hdr.Name)
	content, err := io.ReadAll(tw)
	require.NoError(t, err)
	require.Equal(t, "bootstrap", string(content))
}

func TestGetOriginalBlobLayers(t *testing.T) {
	image := parser.Image{Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
		{MediaType: utils.MediaTypeNydusBlob, Digest: digest.FromString("blob1")},
		{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("bootstrap")},
		{MediaType: utils.MediaTypeNydusBlob, Digest: digest.FromString("blob2")},
	}}}

	layers := getOriginalBlobLayers(image)
	require.Len(t, layers, 2)
	require.Equal(t, digest.FromString("blob1"), layers[0].Digest)
	require.Equal(t, digest.FromString("blob2"), layers[1].Digest)
}

func TestIsSignalKilled(t *testing.T) {
	require.True(t, isSignalKilled(errors.New("signal: killed")))
	require.False(t, isSignalKilled(errors.New("exit status 1")))
}

func TestBuild(t *testing.T) {
	t.Run("localfs success", func(t *testing.T) {
		script := "#!/bin/sh\n" +
			"printf '%s\\n' \"$@\" > \"$OPTIMIZER_ARGS_FILE\"\n" +
			"output=\"\"\n" +
			"while [ $# -gt 0 ]; do\n" +
			"  if [ \"$1\" = \"--output-json\" ]; then output=\"$2\"; shift 2; continue; fi\n" +
			"  shift\n" +
			"done\n" +
			"printf '{\"blobs\":[\"prefetch-blob\"]}' > \"$output\"\n"
		binaryPath, argsPath := createOptimizerBinary(t, script)
		blobID, err := Build(BuildOption{
			BuilderPath:         binaryPath,
			PrefetchFilesPath:   "/tmp/prefetch.files",
			BootstrapPath:       "/tmp/bootstrap.boot",
			BackendType:         "localfs",
			BlobDir:             t.TempDir(),
			OutputBootstrapPath: filepath.Join(t.TempDir(), "optimized.boot"),
			OutputJSONPath:      filepath.Join(t.TempDir(), "output.json"),
		})
		require.NoError(t, err)
		require.Equal(t, "prefetch-blob", blobID)
		args := readOptimizerArgs(t, argsPath)
		require.Contains(t, args, "--blob-dir")
		require.NotContains(t, args, "--backend-type")
	})

	t.Run("remote backend invalid json", func(t *testing.T) {
		script := "#!/bin/sh\n" +
			"output=\"\"\n" +
			"printf '%s\\n' \"$@\" > \"$OPTIMIZER_ARGS_FILE\"\n" +
			"while [ $# -gt 0 ]; do\n" +
			"  if [ \"$1\" = \"--output-json\" ]; then output=\"$2\"; shift 2; continue; fi\n" +
			"  shift\n" +
			"done\n" +
			"printf 'not-json' > \"$output\"\n"
		binaryPath, argsPath := createOptimizerBinary(t, script)
		timeout := 2 * time.Second
		blobID, err := Build(BuildOption{
			BuilderPath:         binaryPath,
			PrefetchFilesPath:   "/tmp/prefetch.files",
			BootstrapPath:       "/tmp/bootstrap.boot",
			BackendType:         "registry",
			BackendConfig:       "{\"scheme\":\"https\"}",
			BlobDir:             t.TempDir(),
			OutputBootstrapPath: filepath.Join(t.TempDir(), "optimized.boot"),
			OutputJSONPath:      filepath.Join(t.TempDir(), "output.json"),
			Timeout:             &timeout,
		})
		require.Empty(t, blobID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal output json file")
		args := readOptimizerArgs(t, argsPath)
		require.Contains(t, args, "--backend-type")
		require.Contains(t, args, "registry")
		require.Contains(t, args, "--backend-config")
	})

	t.Run("missing blob list panics", func(t *testing.T) {
		script := "#!/bin/sh\n" +
			"output=\"\"\n" +
			"while [ $# -gt 0 ]; do\n" +
			"  if [ \"$1\" = \"--output-json\" ]; then output=\"$2\"; shift 2; continue; fi\n" +
			"  shift\n" +
			"done\n" +
			"printf '{}' > \"$output\"\n"
		binaryPath, _ := createOptimizerBinary(t, script)
		require.Panics(t, func() {
			_, _ = Build(BuildOption{
				BuilderPath:         binaryPath,
				PrefetchFilesPath:   "/tmp/prefetch.files",
				BootstrapPath:       "/tmp/bootstrap.boot",
				BackendType:         "registry",
				BackendConfig:       "{}",
				BlobDir:             t.TempDir(),
				OutputBootstrapPath: filepath.Join(t.TempDir(), "optimized.boot"),
				OutputJSONPath:      filepath.Join(t.TempDir(), "output.json"),
			})
		})
	})

	t.Run("empty blob list panics", func(t *testing.T) {
		script := "#!/bin/sh\n" +
			"output=\"\"\n" +
			"while [ $# -gt 0 ]; do\n" +
			"  if [ \"$1\" = \"--output-json\" ]; then output=\"$2\"; shift 2; continue; fi\n" +
			"  shift\n" +
			"done\n" +
			"printf '{\"blobs\":[]}' > \"$output\"\n"
		binaryPath, _ := createOptimizerBinary(t, script)
		require.Panics(t, func() {
			_, _ = Build(BuildOption{
				BuilderPath:         binaryPath,
				PrefetchFilesPath:   "/tmp/prefetch.files",
				BootstrapPath:       "/tmp/bootstrap.boot",
				BackendType:         "registry",
				BackendConfig:       "{}",
				BlobDir:             t.TempDir(),
				OutputBootstrapPath: filepath.Join(t.TempDir(), "optimized.boot"),
				OutputJSONPath:      filepath.Join(t.TempDir(), "output.json"),
			})
		})
	})
}

func TestOptHosts(t *testing.T) {
	opt := Opt{
		Source:         "docker.io/library/alpine:latest",
		Target:         "registry.example.com/alpine:opt",
		SourceInsecure: true,
		TargetInsecure: false,
	}
	hostFunc := hosts(opt)

	credFunc, insecure, err := hostFunc(opt.Source)
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.True(t, insecure)

	credFunc, insecure, err = hostFunc(opt.Target)
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.False(t, insecure)

	credFunc, insecure, err = hostFunc("unknown")
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.False(t, insecure)
}

func TestRemoter(t *testing.T) {
	// Valid reference
	r, err := remoter(Opt{Target: "docker.io/library/busybox:latest", TargetInsecure: false})
	require.NoError(t, err)
	require.NotNil(t, r)

	// Invalid reference
	r, err = remoter(Opt{Target: "INVALID REF!!!", TargetInsecure: false})
	require.Error(t, err)
	require.Nil(t, r)
}

func TestPackToTarUncompressed(t *testing.T) {
	files := []File{
		{Name: EntryBootstrap, Reader: bytes.NewBufferString("boot"), Size: 4},
		{Name: EntryPrefetchFiles, Reader: bytes.NewBufferString("files"), Size: 5},
	}
	reader := packToTar(files, false)
	defer reader.Close()

	tw := tar.NewReader(reader)

	// Should have directory entry "image"
	hdr, err := tw.Next()
	require.NoError(t, err)
	require.Equal(t, "image", hdr.Name)

	// First file
	hdr, err = tw.Next()
	require.NoError(t, err)
	require.Equal(t, filepath.Join("image", EntryBootstrap), hdr.Name)
	data, err := io.ReadAll(tw)
	require.NoError(t, err)
	require.Equal(t, "boot", string(data))

	// Second file
	hdr, err = tw.Next()
	require.NoError(t, err)
	require.Equal(t, filepath.Join("image", EntryPrefetchFiles), hdr.Name)
	data, err = io.ReadAll(tw)
	require.NoError(t, err)
	require.Equal(t, "files", string(data))
}
