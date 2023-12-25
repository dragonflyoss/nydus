// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func makePlatform(osArch string, nydus bool) *ocispec.Platform {
	var platform *ocispec.Platform
	if osArch == "" {
		platform = &ocispec.Platform{
			OS:           "",
			Architecture: "",
		}
	} else {
		platform = &ocispec.Platform{
			OS:           strings.Split(osArch, "/")[0],
			Architecture: strings.Split(osArch, "/")[1],
		}
	}
	if nydus {
		platform.OSFeatures = []string{ManifestOSFeatureNydus}
	} else {
		platform.OSFeatures = nil
	}
	return platform
}

func makeDesc(id string, platform *ocispec.Platform) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("manifest-" + id),
		Size:      10,
		Platform:  platform,
	}
}

func TestIsSupportedArch(t *testing.T) {
	var arch string
	arch = PlatformArchAMD64
	require.Equal(t, IsSupportedArch(arch), true)
	arch = PlatformArchARM64
	require.Equal(t, IsSupportedArch(arch), true)
	arch = "riscv64"
	require.Equal(t, IsSupportedArch(arch), false)
	arch = "unsupported"
	require.Equal(t, IsSupportedArch(arch), false)
}

func TestIsNydusPlatform(t *testing.T) {
	var platform *ocispec.Platform
	platform = makePlatform("linux/amd64", true)
	require.Equal(t, IsNydusPlatform(platform), true)
	platform = makePlatform("linux/arm64", true)
	require.Equal(t, IsNydusPlatform(platform), true)
	platform = makePlatform("linux/amd64", false)
	require.Equal(t, IsNydusPlatform(platform), false)
	platform = makePlatform("linux/arm64", false)
	require.Equal(t, IsNydusPlatform(platform), false)
}

func TestMatchNydusPlatform(t *testing.T) {
	var desc ocispec.Descriptor
	desc = makeDesc("nydus", makePlatform("linux/amd64", true))
	require.Equal(t, MatchNydusPlatform(&desc, "linux", "arm64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "linux", "amd64"), true)
	require.Equal(t, MatchNydusPlatform(&desc, "windows", "amd64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "windows", "arm64"), false)
	desc = makeDesc("nydus", makePlatform("linux/amd64", false))
	require.Equal(t, MatchNydusPlatform(&desc, "linux", "arm64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "linux", "amd64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "windows", "amd64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "windows", "arm64"), false)
	desc = makeDesc("nydus", makePlatform("windows/arm64", true))
	require.Equal(t, MatchNydusPlatform(&desc, "windows", "arm64"), true)
	require.Equal(t, MatchNydusPlatform(&desc, "windows", "amd64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "linux", "arm64"), false)
	require.Equal(t, MatchNydusPlatform(&desc, "linux", "amd64"), false)
}

func TestIsEmptyString(t *testing.T) {
	var str = ""
	require.Equal(t, IsEmptyString(str), true)
	str = "test"
	require.Equal(t, IsEmptyString(str), false)
}

func TestIsPathExists(t *testing.T) {
	var tempdir = "./test/"
	err := os.MkdirAll(tempdir, 0666)
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)
	require.Equal(t, IsPathExists(tempdir), true)
	var path = "UnexistFolder"
	require.Equal(t, IsPathExists(path), false)
}

func createArchive(files []string, buf io.Writer) error {
	// Create new Writers for gzip and tar
	// These writers are chained. Writing to the tar writer will
	// write to the gzip writer which in turn will write to
	// the "buf" writer
	gw := gzip.NewWriter(buf)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	// Iterate over files and add them to the tar archive
	for _, file := range files {
		err := addToArchive(tw, file)
		if err != nil {
			return err
		}
	}
	return nil
}

func addToArchive(tw *tar.Writer, filename string) error {
	// Open the file which will be written into the archive
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	// Get FileInfo about our file providing file size, mode, etc.
	info, err := file.Stat()
	if err != nil {
		return err
	}
	// Create a tar Header from the FileInfo data
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}
	// Use full path as name (FileInfoHeader only takes the basename)
	// If we don't do this the directory strucuture would
	// not be preserved
	// https://golang.org/src/archive/tar/common.go?#L626
	header.Name = filename
	// Write file header to the tar archive
	err = tw.WriteHeader(header)
	if err != nil {
		return err
	}
	// Copy file content to tar archive
	_, err = io.Copy(tw, file)
	if err != nil {
		return err
	}
	return nil
}

func TestUnpackFile(t *testing.T) {
	fileName := "example.txt"
	dirName := "test"
	mockData := "this is a test data"
	// Create file1
	file1, err := os.Create(fileName)
	require.NoError(t, err)
	defer file1.Close()
	defer os.RemoveAll(file1.Name())
	_, err = io.WriteString(file1, mockData)
	require.NoError(t, err)
	// Create file2
	err = os.MkdirAll(dirName, 0666)
	defer os.RemoveAll(dirName)
	require.NoError(t, err)
	file2, err := os.Create(dirName + fileName)
	require.NoError(t, err)
	defer file2.Close()
	defer os.RemoveAll(file2.Name())
	_, err = io.WriteString(file2, mockData)
	require.NoError(t, err)
	// Files which to include in the tar.gz archive
	files := []string{file1.Name(), file2.Name()}
	// Create output file
	targzName := "output.tar.gz"
	out, err := os.Create(targzName)
	require.NoError(t, err)
	defer out.Close()
	defer os.Remove(targzName)
	// Create the archive and write the output to the "out" Writer
	err = createArchive(files, out)
	require.NoError(t, err)
	// Archive created successfully
	targzFile, err := os.Open(out.Name())
	require.NoError(t, err)
	defer targzFile.Close()
	outputName := "output.txt"
	err = UnpackFile(targzFile, file1.Name(), outputName)
	require.NoError(t, err)
	defer os.Remove(outputName)
}

func TestHashFile(t *testing.T) {
	file, err := os.CreateTemp("", "tempFile")
	require.NoError(t, err)
	defer os.RemoveAll(file.Name())

	_, err = file.WriteString("123456")
	require.NoError(t, err)
	file.Sync()

	hashSum, err := HashFile(file.Name())
	require.NoError(t, err)
	require.Len(t, hashSum, 32)
}

func TestMarshalToDesc(t *testing.T) {
	config := ocispec.Image{
		Config: ocispec.ImageConfig{},
		RootFS: ocispec.RootFS{
			Type: "layers",
			// Layers from manifest must be match image config.
			DiffIDs: []digest.Digest{},
		},
	}
	configDesc, configBytes, err := MarshalToDesc(config, ocispec.MediaTypeImageConfig)
	require.NoError(t, err)
	require.Equal(t, "application/vnd.oci.image.config.v1+json", configDesc.MediaType)
	require.Equal(t, "sha256:1475e1cf0118aa3ddadbc8ae05cd5d5e151b63784e1e062de226e70fced50a0f", configDesc.Digest.String())
	require.Equal(t, int64(len(configBytes)), configDesc.Size)
}

func TestWithRetry(t *testing.T) {
	err := WithRetry(func() error {
		_, err := http.Get("http://localhost:5000")
		return err
	})
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
}

func TestRetryWithHTTP(t *testing.T) {
	require.True(t, RetryWithHTTP(errors.Wrap(http.ErrSchemeMismatch, "parse Nydus image")))
	require.False(t, RetryWithHTTP(nil))
}

func TestGetNydusFsVersionOrDefault(t *testing.T) {
	testAnnotations := make(map[string]string)
	fsVersion := GetNydusFsVersionOrDefault(testAnnotations, V5)
	require.Equal(t, fsVersion, V5)

	fsVersion = GetNydusFsVersionOrDefault(nil, V6)
	require.Equal(t, fsVersion, V6)

	testAnnotations[LayerAnnotationNydusFsVersion] = "5"
	fsVersion = GetNydusFsVersionOrDefault(testAnnotations, V6)
	require.Equal(t, fsVersion, V5)

	testAnnotations[LayerAnnotationNydusFsVersion] = "6"
	fsVersion = GetNydusFsVersionOrDefault(testAnnotations, V5)
	require.Equal(t, fsVersion, V6)

	testAnnotations[LayerAnnotationNydusFsVersion] = "7"
	fsVersion = GetNydusFsVersionOrDefault(testAnnotations, V5)
	require.Equal(t, fsVersion, V5)
}
