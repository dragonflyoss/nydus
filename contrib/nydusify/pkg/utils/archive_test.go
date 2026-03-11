// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackTargzInfo(t *testing.T) {
	file, err := os.CreateTemp("", "nydusify-archive-test")
	assert.Nil(t, err)
	defer os.RemoveAll(file.Name())

	err = os.WriteFile(file.Name(), make([]byte, 1024*200), 0666)
	assert.Nil(t, err)

	digest, size, err := PackTargzInfo(file.Name(), "test", true)
	assert.Nil(t, err)

	assert.Equal(t, "sha256:6cdd1b26d54d5852fbea95a81cbb25383975b70b4ffad9f9b6d25c7a434a51eb", digest.String())
	assert.Equal(t, size, int64(315))
}

func TestUnpackTargz(t *testing.T) {
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	uid := os.Getuid()
	gid := os.Getgid()
	payload := []byte("nydus archive data")
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{
		Name:     "nested",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		Uid:      uid,
		Gid:      gid,
	}))
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{
		Name:     "nested/source.txt",
		Mode:     0o644,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
		Uid:      uid,
		Gid:      gid,
	}))
	_, err := tarWriter.Write(payload)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())

	dstDir := filepath.Join(t.TempDir(), "unpacked")
	require.NoError(t, UnpackTargz(context.Background(), dstDir, bytes.NewReader(buffer.Bytes()), false))

	content, err := os.ReadFile(filepath.Join(dstDir, "nested", "source.txt"))
	require.NoError(t, err)
	assert.Equal(t, "nydus archive data", string(content))
}

func TestUnpackFromTar(t *testing.T) {
	var buffer bytes.Buffer
	tarWriter := tar.NewWriter(&buffer)
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{
		Name:     "subdir",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}))

	payload := []byte("payload from tar")
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{
		Name:     "subdir/file.txt",
		Mode:     0o644,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}))
	_, err := tarWriter.Write(payload)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())

	dstDir := filepath.Join(t.TempDir(), "untar")
	require.NoError(t, UnpackFromTar(bytes.NewReader(buffer.Bytes()), dstDir))

	content, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, string(payload), string(content))
}

func TestUnpackTargzInvalidStream(t *testing.T) {
	invalid := io.NopCloser(bytes.NewReader([]byte("not-a-tar-gz")))
	defer invalid.Close()

	err := UnpackTargz(context.Background(), t.TempDir(), invalid, false)
	require.Error(t, err)
}

func TestPackTargzWithoutCompression(t *testing.T) {
	tempDir := t.TempDir()
	sourceFile := filepath.Join(tempDir, "plain.txt")
	require.NoError(t, os.WriteFile(sourceFile, []byte("plain archive"), 0o644))

	reader, err := PackTargz(sourceFile, "plain.txt", false)
	require.NoError(t, err)
	defer reader.Close()

	tarReader := tar.NewReader(reader)
	_, err = tarReader.Next()
	require.NoError(t, err)
	header, err := tarReader.Next()
	require.NoError(t, err)
	assert.Equal(t, "plain.txt", header.Name)

	content, err := io.ReadAll(tarReader)
	require.NoError(t, err)
	assert.Equal(t, "plain archive", string(content))
}

func TestPackTargzCompressedStream(t *testing.T) {
	tempDir := t.TempDir()
	sourceFile := filepath.Join(tempDir, "compressed.txt")
	require.NoError(t, os.WriteFile(sourceFile, []byte("compressed archive"), 0o644))

	reader, err := PackTargz(sourceFile, "compressed.txt", true)
	require.NoError(t, err)
	defer reader.Close()

	gzipReader, err := gzip.NewReader(reader)
	require.NoError(t, err)
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	_, err = tarReader.Next()
	require.NoError(t, err)
	header, err := tarReader.Next()
	require.NoError(t, err)
	assert.Equal(t, "compressed.txt", header.Name)

	content, err := io.ReadAll(tarReader)
	require.NoError(t, err)
	assert.Equal(t, "compressed archive", string(content))
}
