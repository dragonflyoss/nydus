// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type Layer struct {
	workDir  string
	FileTree map[string]*File
}

func NewLayer(t *testing.T, workDir string) *Layer {
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	return &Layer{
		workDir:  workDir,
		FileTree: make(map[string]*File),
	}
}

func (l *Layer) CreateFile(t *testing.T, name string, data []byte) {
	err := os.WriteFile(filepath.Join(l.workDir, name), data, 0644)
	require.NoError(t, err)
}

func (l *Layer) CreateLargeFile(t *testing.T, name string, sizeGB int) {
	f, err := os.Create(filepath.Join(l.workDir, name))
	require.NoError(t, err)
	defer func() {
		f.Close()
	}()

	_, err = io.CopyN(f, rand.Reader, int64(sizeGB)<<30)
	assert.Nil(t, err)
}

func (l *Layer) CreateLargeFileWithCustomizedContent(t *testing.T, name string, sizeGB int, content string) {
	f, err := os.Create(filepath.Join(l.workDir, name))
	require.NoError(t, err)
	defer func() {
		f.Close()
	}()

	fileSizeInBytes := int64(sizeGB) << 30 // 将 GB 转换为字节

	bytesWritten := int64(0)
	for bytesWritten < fileSizeInBytes {
		bytesToWrite := min(fileSizeInBytes-bytesWritten, int64(len(content)))
		_, err := f.WriteString(content[:bytesToWrite])
		assert.Nil(t, err)
		bytesWritten += bytesToWrite
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (l *Layer) CreateHoledFile(t *testing.T, name string, data []byte, offset, fileSize int64) {
	f, err := os.Create(filepath.Join(l.workDir, name))
	require.NoError(t, err)
	defer func() {
		f.Close()
	}()

	err = f.Truncate(fileSize)
	require.NoError(t, err)

	_, err = f.WriteAt(data, offset)
	require.NoError(t, err)
}

func (l *Layer) CreateDir(t *testing.T, name string) {
	err := os.MkdirAll(filepath.Join(l.workDir, name), 0755)
	require.NoError(t, err)
}

func (l *Layer) CreateSymlink(t *testing.T, name string, target string) {
	err := os.Symlink(filepath.Join(l.workDir, target), filepath.Join(l.workDir, name))
	require.NoError(t, err)
}

func (l *Layer) CreateHardlink(t *testing.T, name string, target string) {
	err := os.Link(filepath.Join(l.workDir, target), filepath.Join(l.workDir, name))
	require.NoError(t, err)
}

func (l *Layer) CreateSpecialFile(t *testing.T, name string, devType uint32) {
	err := syscall.Mknod(filepath.Join(l.workDir, name), devType|0666, int(unix.Mkdev(255, 0)))
	require.NoError(t, err)
}

func (l *Layer) SetXattr(t *testing.T, name string, key string, data []byte) {
	err := xattr.Set(filepath.Join(l.workDir, name), key, data)
	require.NoError(t, err)
}

func (l *Layer) CreateWhiteout(t *testing.T, target string) {
	name := filepath.Base(target)
	dir := filepath.Dir(target)
	err := os.WriteFile(filepath.Join(l.workDir, filepath.Join(dir, ".wh."+name)), nil, 0644)
	require.NoError(t, err)
}

func (l *Layer) CreateOpaque(t *testing.T, targetDir string) {
	err := os.WriteFile(filepath.Join(l.workDir, targetDir, ".wh..wh..opq"), nil, 0644)
	require.NoError(t, err)
}

func (l *Layer) TargetPath(t *testing.T, path string) string {
	name, err := filepath.Rel(l.workDir, path)
	require.NoError(t, err)
	return name
}

func (l *Layer) Pack(t *testing.T, packOption converter.PackOption, blobDir string) digest.Digest {
	// Output OCI tar stream
	ociTar := l.ToOCITar(t)
	defer ociTar.Close()
	l.recordFileTree(t)

	// Pack OCI tar to nydus native blob
	blob, err := os.CreateTemp(blobDir, "blob-")
	require.NoError(t, err)
	defer blob.Close()
	blobDigester := digest.Canonical.Digester()
	blobWriter := io.MultiWriter(blob, blobDigester.Hash())
	twc, err := converter.Pack(context.Background(), blobWriter, packOption)
	require.NoError(t, err)
	_, err = io.Copy(twc, ociTar)
	require.NoError(t, err)
	err = twc.Close()
	require.NoError(t, err)
	blobDigest := blobDigester.Digest()
	err = os.Rename(blob.Name(), filepath.Join(blobDir, blobDigest.Hex()))
	require.NoError(t, err)

	return blobDigest
}

func (l *Layer) PackRef(t *testing.T, ctx Context, blobDir string, compress bool) (digest.Digest, digest.Digest) {
	// Output OCI tar stream
	ociTar := l.ToOCITar(t)
	defer ociTar.Close()
	l.recordFileTree(t)

	var ociBlobReader io.ReadCloser
	if compress {
		var gzipData bytes.Buffer
		gzipWriter := gzip.NewWriter(&gzipData)
		_, err := io.Copy(gzipWriter, ociTar)
		require.NoError(t, err)
		err = gzipWriter.Close()
		require.NoError(t, err)
		dupGzipData := gzipData
		ociBlobReader = io.NopCloser(&dupGzipData)
	} else {
		ociBlobReader = io.NopCloser(ociTar)
	}

	// Pack OCI blob to nydus zran blob
	rafsBlob, err := os.CreateTemp(blobDir, "rafs-blob-")
	require.NoError(t, err)
	defer rafsBlob.Close()
	rafsBlobDigester := digest.Canonical.Digester()
	rafsBlobWriter := io.MultiWriter(rafsBlob, rafsBlobDigester.Hash())
	twc, err := converter.Pack(context.Background(), rafsBlobWriter, converter.PackOption{
		BuilderPath: ctx.Binary.Builder,
		OCIRef:      true,
	})
	require.NoError(t, err)

	ociBlobDigester := digest.Canonical.Digester()
	ociBlob, err := os.CreateTemp(blobDir, "oci-blob-")
	require.NoError(t, err)

	_, err = io.Copy(io.MultiWriter(twc, ociBlobDigester.Hash(), ociBlob), ociBlobReader)
	require.NoError(t, err)
	err = twc.Close()
	require.NoError(t, err)

	ociBlobDigest := ociBlobDigester.Digest()
	err = os.Rename(ociBlob.Name(), filepath.Join(blobDir, ociBlobDigest.Hex()))
	require.NoError(t, err)

	rafsBlobDigest := rafsBlobDigester.Digest()
	err = os.Rename(rafsBlob.Name(), filepath.Join(blobDir, rafsBlobDigest.Hex()))
	require.NoError(t, err)

	return ociBlobDigest, rafsBlobDigest
}

func (l *Layer) Overlay(t *testing.T, upper *Layer) *Layer {
	// Handle whiteout/opaque files
	for upperName := range upper.FileTree {
		name := filepath.Base(upperName)
		if name == ".wh..wh..opq" {
			for lowerName := range l.FileTree {
				dir := filepath.Dir(upperName)
				if strings.HasPrefix(lowerName, dir) && lowerName != dir {
					delete(l.FileTree, lowerName)
				}
			}
		} else if strings.HasPrefix(name, ".wh.") {
			targetName := name[4:]
			target := filepath.Join(filepath.Dir(upperName), targetName)
			delete(l.FileTree, target)
		}
	}
	// Handle added/updated files
	for lowerName := range l.FileTree {
		for upperName, upperFile := range upper.FileTree {
			name := filepath.Base(upperName)
			if name == ".wh..wh..opq" || strings.HasPrefix(name, ".wh.") {
				continue
			}
			// Updated file
			if lowerName == upperName {
				l.FileTree[lowerName] = upperFile
			}
			// Added file
			if l.FileTree[upperName] == nil {
				l.FileTree[upperName] = upperFile
			}
		}
	}

	return l
}

func (l *Layer) recordFileTree(t *testing.T) {
	l.FileTree = map[string]*File{}
	filepath.Walk(l.workDir, func(path string, fi os.FileInfo, err error) error {
		targetPath := l.TargetPath(t, path)
		l.FileTree[targetPath] = NewFile(t, path, targetPath)
		return nil
	})
}

func (l *Layer) ToOCITar(t *testing.T) io.ReadCloser {
	return archive.Diff(context.Background(), "", l.workDir)
}

func MergeLayers(t *testing.T, ctx Context, mergeOption converter.MergeOption, layers []converter.Layer) ([]digest.Digest, string) {
	for idx := range layers {
		ra, err := local.OpenReader(filepath.Join(ctx.Env.BlobDir, layers[idx].Digest.Hex()))
		require.NoError(t, err)
		defer ra.Close()
		layers[idx].ReaderAt = ra
	}

	bootstrap, err := os.CreateTemp(ctx.Env.WorkDir, "bootstrap-")
	require.NoError(t, err)
	defer bootstrap.Close()
	actualDigests, err := converter.Merge(context.Background(), layers, bootstrap, mergeOption)
	require.NoError(t, err)

	return actualDigests, bootstrap.Name()
}
