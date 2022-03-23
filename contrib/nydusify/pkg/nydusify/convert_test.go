package converter

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/nydusify/tool"
)

func hugeString(size int) string {
	var buf strings.Builder
	buf.Grow(size)

	data := make([]byte, size)
	rand.Read(data)
	buf.Write(data)

	return buf.String()
}

func dropCache(t *testing.T) {
	cmd := exec.Command("sh", "-c", "echo 3 > /proc/sys/vm/drop_caches")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run())
}

func ensureFile(t *testing.T, name string) {
	_, err := os.Stat(name)
	require.NoError(t, err)
}

func ensureNoFile(t *testing.T, name string) {
	_, err := os.Stat(name)
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func writeFileToTar(t *testing.T, tw *tar.Writer, name string, data string) {
	hdr := &tar.Header{
		Name: name,
		Mode: 0444,
		Size: int64(len(data)),
	}
	err := tw.WriteHeader(hdr)
	require.NoError(t, err)

	io.Copy(tw, bytes.NewReader([]byte(data)))
	require.NoError(t, err)
}

func writeDirToTar(t *testing.T, tw *tar.Writer, name string) {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0444,
		Typeflag: tar.TypeDir,
	}
	err := tw.WriteHeader(hdr)
	require.NoError(t, err)
}

var expectedFileTree = map[string]string{
	"dir-1":        "",
	"dir-1/file-2": "lower-file-2",
	"dir-2":        "",
	"dir-2/file-1": hugeString(1024 * 1024 * 3),
	"dir-2/file-2": "upper-file-2",
	"dir-2/file-3": "upper-file-3",
}

func buildChunkDictTar(t *testing.T) io.ReadCloser {
	pr, pw := io.Pipe()
	tw := tar.NewWriter(pw)

	go func() {
		writeDirToTar(t, tw, "dir-1")
		writeFileToTar(t, tw, "dir-1/file-1", "lower-file-1")
		writeFileToTar(t, tw, "dir-1/file-2", "lower-file-2")
		writeFileToTar(t, tw, "dir-1/file-3", "lower-file-3")

		require.NoError(t, tw.Close())
	}()

	return pr
}

func buildOCILowerTar(t *testing.T) io.ReadCloser {
	pr, pw := io.Pipe()
	tw := tar.NewWriter(pw)

	go func() {
		writeDirToTar(t, tw, "dir-1")
		writeFileToTar(t, tw, "dir-1/file-1", "lower-file-1")
		writeFileToTar(t, tw, "dir-1/file-2", "lower-file-2")

		writeDirToTar(t, tw, "dir-2")
		writeFileToTar(t, tw, "dir-2/file-1", "lower-file-1")

		require.NoError(t, tw.Close())
	}()

	return pr
}

func buildOCIUpperTar(t *testing.T) io.ReadCloser {
	pr, pw := io.Pipe()
	tw := tar.NewWriter(pw)

	go func() {
		writeDirToTar(t, tw, "dir-1")
		writeFileToTar(t, tw, "dir-1/.wh.file-1", "")

		writeDirToTar(t, tw, "dir-2")
		writeFileToTar(t, tw, "dir-2/.wh..wh..opq", "")
		writeFileToTar(t, tw, "dir-2/file-1", expectedFileTree["dir-2/file-1"])
		writeFileToTar(t, tw, "dir-2/file-2", "upper-file-2")
		writeFileToTar(t, tw, "dir-2/file-3", "upper-file-3")

		require.NoError(t, tw.Close())
	}()

	return pr
}

func convertLayer(t *testing.T, source io.ReadCloser, chunkDict, workDir string) (io.Reader, digest.Digest) {
	blobDigester := digest.Canonical.Digester()

	var data bytes.Buffer
	writer := bufio.NewWriter(&data)

	defer source.Close()
	nydusTarReader, err := ConvertWithChunkDict(context.TODO(), source, chunkDict)
	require.NoError(t, err)
	defer nydusTarReader.Close()

	_, err = io.Copy(writer, io.TeeReader(nydusTarReader, blobDigester.Hash()))
	require.NoError(t, err)

	blobDigest := blobDigester.Digest()
	file, err := os.Create(filepath.Join(workDir, blobDigest.Hex()))
	require.NoError(t, err)
	defer file.Close()
	file.Write(data.Bytes())

	return bufio.NewReader(&data), blobDigest
}

func verify(t *testing.T, workDir string) {
	mountDir := filepath.Join(workDir, "mnt")
	blobDir := filepath.Join(workDir, "blobs")
	config := tool.NydusdConfig{
		EnablePrefetch: false,
		NydusdPath:     "nydusd",
		BootstrapPath:  filepath.Join(workDir, "bootstrap"),
		ConfigPath:     filepath.Join(workDir, "nydusd-config.json"),
		BackendType:    "localfs",
		BackendConfig:  fmt.Sprintf(`{"dir": "%s"}`, blobDir),
		BlobCacheDir:   filepath.Join(workDir, "cache"),
		APISockPath:    filepath.Join(workDir, "nydusd-api.sock"),
		MountPath:      mountDir,
	}

	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)
	defer nydusd.Umount()

	actualFileTree := map[string]string{}
	err = filepath.WalkDir(mountDir, func(path string, entry fs.DirEntry, err error) error {
		require.Nil(t, err)
		info, err := entry.Info()
		require.NoError(t, err)

		targetPath, err := filepath.Rel(mountDir, path)
		require.NoError(t, err)

		if targetPath == "." {
			return nil
		}

		data := ""
		if !info.IsDir() {
			file, err := os.Open(path)
			require.NoError(t, err)
			defer file.Close()
			_data, err := ioutil.ReadAll(file)
			require.NoError(t, err)
			data = string(_data)
		}
		actualFileTree[targetPath] = data

		return nil
	})
	require.NoError(t, err)

	require.Equal(t, expectedFileTree, actualFileTree)
}

func buildChunkDict(t *testing.T, workDir string) (string, string) {
	dictOCITarReader := buildChunkDictTar(t)

	blobDir := filepath.Join(workDir, "blobs")
	lowerNydusTarReader, lowerNydusBlobDigest := convertLayer(t, dictOCITarReader, "", blobDir)

	layers := []Layer{
		{
			Digest: lowerNydusBlobDigest,
			Reader: lowerNydusTarReader,
		},
	}

	finalBootstrapReader, err := Merge(context.TODO(), layers)
	require.NoError(t, err)
	defer finalBootstrapReader.Close()

	bootstrapPath := filepath.Join(workDir, "dict-bootstrap")
	bootstrap, err := os.Create(bootstrapPath)
	require.NoError(t, err)
	defer bootstrap.Close()
	_, err = io.Copy(bootstrap, finalBootstrapReader)
	require.NoError(t, err)

	dictBlobPath := ""
	err = filepath.WalkDir(blobDir, func(path string, entry fs.DirEntry, err error) error {
		require.NoError(t, err)
		if path == blobDir {
			return nil
		}
		dictBlobPath = path
		return nil
	})
	require.NoError(t, err)

	return bootstrapPath, filepath.Base(dictBlobPath)
}

// sudo go test -v -count=1 -run TestConverter ./pkg/nydusify
func TestConverter(t *testing.T) {
	workDir, err := ioutil.TempDir("", "nydus-converter-test-")
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	lowerOCITarReader := buildOCILowerTar(t)
	upperOCITarReader := buildOCIUpperTar(t)

	blobDir := filepath.Join(workDir, "blobs")
	err = os.MkdirAll(blobDir, 0755)
	require.NoError(t, err)

	cacheDir := filepath.Join(workDir, "cache")
	err = os.MkdirAll(cacheDir, 0755)
	require.NoError(t, err)

	mountDir := filepath.Join(workDir, "mnt")
	err = os.MkdirAll(mountDir, 0755)
	require.NoError(t, err)

	chunkDictBootstrapPath, chunkDictBlobHash := buildChunkDict(t, workDir)

	lowerNydusTarReader, lowerNydusBlobDigest := convertLayer(t, lowerOCITarReader, chunkDictBootstrapPath, blobDir)
	upperNydusTarReader, upperNydusBlobDigest := convertLayer(t, upperOCITarReader, chunkDictBootstrapPath, blobDir)

	layers := []Layer{
		{
			Digest: lowerNydusBlobDigest,
			Reader: lowerNydusTarReader,
		},
		{
			Digest: upperNydusBlobDigest,
			Reader: upperNydusTarReader,
		},
	}

	finalBootstrapReader, err := MergeWithChunkDict(context.TODO(), layers, chunkDictBootstrapPath)
	require.NoError(t, err)
	defer finalBootstrapReader.Close()

	bootstrapPath := filepath.Join(workDir, "bootstrap")
	bootstrap, err := os.Create(bootstrapPath)
	require.NoError(t, err)
	defer bootstrap.Close()
	_, err = io.Copy(bootstrap, finalBootstrapReader)
	require.NoError(t, err)

	verify(t, workDir)
	dropCache(t)
	verify(t, workDir)

	ensureFile(t, filepath.Join(cacheDir, chunkDictBlobHash)+".chunk_map")
	ensureNoFile(t, filepath.Join(cacheDir, lowerNydusBlobDigest.Hex())+".chunk_map")
	ensureFile(t, filepath.Join(cacheDir, upperNydusBlobDigest.Hex())+".chunk_map")
}
