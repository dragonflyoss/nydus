/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockBootstrapEntries = []string{
		nydus.BootstrapFileNameInLayer + "=bootstrap bytes",
		"image/blob.blob.meta=metadata bytes",
		"image/ignored=not an extracted artifact",
	}

	mockBlobMetaData = bytes.Repeat([]byte("blob metadata"), 4096)

	mockDestinationData = []byte("original destination")

	mockBlobData = bytes.Repeat([]byte("blob data"), 4096)

	errBlobReader = errors.New("blob reader failed")
)

type mockContentStore struct {
	content.Store
	openErr error
	readErr error
	readers []*mockReaderAt
}

func (s *mockContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}

	ra, err := s.Store.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}

	r := &mockReaderAt{ReaderAt: ra, readErr: s.readErr}
	s.readers = append(s.readers, r)

	return r, nil
}

type mockReaderAt struct {
	content.ReaderAt
	readErr error
	closed  bool
}

func (r *mockReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.readErr != nil {
		n, err := r.ReaderAt.ReadAt(p[:len(p)/2], off)
		if err != nil {
			return n, err
		}

		return n, r.readErr
	}

	return r.ReaderAt.ReadAt(p, off)
}

func (r *mockReaderAt) Close() error {
	r.closed = true
	return r.ReaderAt.Close()
}

func mockFile(t *testing.T, path string, data []byte) string {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockGzip(t *testing.T, data []byte) []byte {
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	return compressed.Bytes()
}

func mockBlobFooter(magic string, flags uint32) []byte {
	footer := make([]byte, nydus.NydusBlobFooterSize)
	copy(footer, magic)
	binary.LittleEndian.PutUint32(footer[12:], flags)

	return footer
}

func TestExtractBootstrapLayer(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, dest string) []byte
		expect func(t *testing.T, dest, bootstrap string, blobMetas []string, err error)
	}{
		{
			name: "extract bootstrap and blob meta",
			mock: func(t *testing.T, dest string) []byte {
				return mockTarLayer(t, mockBootstrapEntries...)
			},
			expect: func(t *testing.T, dest, bootstrap string, blobMetas []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(filepath.Join(dest, "image.boot"), bootstrap)
				assert.Equal([]string{filepath.Join(dest, "blob.blob.meta")}, blobMetas)

				data, err := os.ReadFile(filepath.Join(dest, "image.boot"))
				assert.NoError(err)
				assert.Equal("bootstrap bytes", string(data))

				data, err = os.ReadFile(filepath.Join(dest, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal("metadata bytes", string(data))

				entries, err := os.ReadDir(dest)
				assert.NoError(err)
				assert.Len(entries, 2)
			},
		},
		{
			name: "missing bootstrap",
			mock: func(t *testing.T, dest string) []byte {
				return mockTarLayer(t, mockBootstrapEntries[1:]...)
			},
			expect: func(t *testing.T, dest, bootstrap string, blobMetas []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "not found in layer")
				assert.Empty(bootstrap)
				assert.Empty(blobMetas)
			},
		},
		{
			name: "truncated bootstrap",
			mock: func(t *testing.T, dest string) []byte {
				layer := mockTarLayer(t, mockBootstrapEntries...)
				return layer[:bytes.Index(layer, []byte("bootstrap bytes"))+1]
			},
			expect: func(t *testing.T, dest, bootstrap string, blobMetas []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write bootstrap file")
				assert.ErrorIs(err, io.ErrUnexpectedEOF)
				assert.Empty(bootstrap)
				assert.Empty(blobMetas)
			},
		},
		{
			name: "truncated blob meta",
			mock: func(t *testing.T, dest string) []byte {
				layer := mockTarLayer(t, mockBootstrapEntries...)
				return layer[:bytes.Index(layer, []byte("metadata bytes"))+1]
			},
			expect: func(t *testing.T, dest, bootstrap string, blobMetas []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write blob meta")
				assert.ErrorIs(err, io.ErrUnexpectedEOF)
				assert.Empty(bootstrap)
				assert.Empty(blobMetas)
			},
		},
		{
			name: "bootstrap output blocked",
			mock: func(t *testing.T, dest string) []byte {
				if err := os.Mkdir(filepath.Join(dest, "image.boot"), 0o700); err != nil {
					t.Fatal(err)
				}

				return mockTarLayer(t, mockBootstrapEntries...)
			},
			expect: func(t *testing.T, dest, bootstrap string, blobMetas []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write bootstrap file")
				assert.Empty(bootstrap)
				assert.Empty(blobMetas)
			},
		},
		{
			name: "blob meta output blocked",
			mock: func(t *testing.T, dest string) []byte {
				if err := os.Mkdir(filepath.Join(dest, "blob.blob.meta"), 0o700); err != nil {
					t.Fatal(err)
				}

				return mockTarLayer(t, mockBootstrapEntries...)
			},
			expect: func(t *testing.T, dest, bootstrap string, blobMetas []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write blob meta")
				assert.Empty(bootstrap)
				assert.Empty(blobMetas)
			},
		},
	}

	for _, tc := range tests {
		for _, encoding := range []string{"tar", "gzip"} {
			t.Run(tc.name+" in "+encoding, func(t *testing.T) {
				cs, err := local.NewStore(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}

				dest := t.TempDir()
				data := tc.mock(t, dest)
				if encoding == "gzip" {
					data = mockGzip(t, data)
				}

				desc := mockBlob(t, cs, ocispec.MediaTypeImageLayer, data)
				bootstrap, blobMetas, err := ExtractBootstrapLayer(context.Background(), cs, desc, dest)

				tc.expect(t, dest, bootstrap, blobMetas, err)
			})
		}
	}
}

func TestLinkBlobMetaFiles(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, cacheDir string) []string
		expect func(t *testing.T, cacheDir string, blobMetaPaths []string, err error)
	}{
		{
			name: "link the same blob meta concurrently",
			mock: func(t *testing.T, cacheDir string) []string {
				return slices.Repeat([]string{mockFile(t, filepath.Join(t.TempDir(), "blob.blob.meta"), mockBlobMetaData)}, 32)
			},
			expect: func(t *testing.T, cacheDir string, blobMetaPaths []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(LinkBlobMetaFiles(context.Background(), blobMetaPaths[:1], cacheDir))

				data, err := os.ReadFile(filepath.Join(cacheDir, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal(mockBlobMetaData, data)

				entries, err := os.ReadDir(cacheDir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "copy across filesystems",
			mock: func(t *testing.T, cacheDir string) []string {
				if runtime.GOOS != "linux" {
					t.Skip("cross-filesystem copy requires /dev/shm")
				}

				dir, err := os.MkdirTemp("/dev/shm", "nydus-blob-meta-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

				return slices.Repeat([]string{mockFile(t, filepath.Join(dir, "blob.blob.meta"), mockBlobMetaData)}, 32)
			},
			expect: func(t *testing.T, cacheDir string, blobMetaPaths []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(os.Link(blobMetaPaths[0], filepath.Join(cacheDir, "hardlink-probe")), syscall.EXDEV)
				assert.NoError(err)
				assert.NoError(os.Remove(blobMetaPaths[0]))

				data, err := os.ReadFile(filepath.Join(cacheDir, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal(mockBlobMetaData, data)

				entries, err := os.ReadDir(cacheDir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "missing source",
			mock: func(t *testing.T, cacheDir string) []string {
				return []string{filepath.Join(t.TempDir(), "blob.blob.meta")}
			},
			expect: func(t *testing.T, cacheDir string, blobMetaPaths []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)

				entries, err := os.ReadDir(cacheDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "source is a directory",
			mock: func(t *testing.T, cacheDir string) []string {
				src := filepath.Join(t.TempDir(), "blob.blob.meta")
				if err := os.Mkdir(src, 0o700); err != nil {
					t.Fatal(err)
				}

				return []string{src}
			},
			expect: func(t *testing.T, cacheDir string, blobMetaPaths []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "copy data")

				entries, err := os.ReadDir(cacheDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "destination is a directory",
			mock: func(t *testing.T, cacheDir string) []string {
				if err := os.Mkdir(filepath.Join(cacheDir, "blob.blob.meta"), 0o700); err != nil {
					t.Fatal(err)
				}

				return []string{mockFile(t, filepath.Join(t.TempDir(), "blob.blob.meta"), mockBlobMetaData)}
			},
			expect: func(t *testing.T, cacheDir string, blobMetaPaths []string, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.DirExists(filepath.Join(cacheDir, "blob.blob.meta"))

				entries, err := os.ReadDir(cacheDir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "destination is a dangling symlink",
			mock: func(t *testing.T, cacheDir string) []string {
				if err := os.Symlink("missing", filepath.Join(cacheDir, "blob.blob.meta")); err != nil {
					t.Fatal(err)
				}

				return []string{mockFile(t, filepath.Join(t.TempDir(), "blob.blob.meta"), mockBlobMetaData)}
			},
			expect: func(t *testing.T, cacheDir string, blobMetaPaths []string, err error) {
				assert := assert.New(t)
				assert.Error(err)

				target, err := os.Readlink(filepath.Join(cacheDir, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal("missing", target)

				entries, err := os.ReadDir(cacheDir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			blobMetaPaths := tc.mock(t, cacheDir)
			err := LinkBlobMetaFiles(context.Background(), blobMetaPaths, cacheDir)

			tc.expect(t, cacheDir, blobMetaPaths, err)
		})
	}
}

func TestCopyFile(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, dir string) (string, string)
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name: "replace destination",
			mock: func(t *testing.T, dir string) (string, string) {
				return mockFile(t, filepath.Join(t.TempDir(), "source"), mockBlobMetaData), mockFile(t, filepath.Join(dir, "blob.blob.meta"), mockDestinationData)
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				data, err := os.ReadFile(filepath.Join(dir, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal(mockBlobMetaData, data)

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "missing source",
			mock: func(t *testing.T, dir string) (string, string) {
				return filepath.Join(t.TempDir(), "source"), mockFile(t, filepath.Join(dir, "blob.blob.meta"), mockDestinationData)
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open source")

				data, err := os.ReadFile(filepath.Join(dir, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal(mockDestinationData, data)

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "source is a directory",
			mock: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(t.TempDir(), "source")
				if err := os.Mkdir(src, 0o700); err != nil {
					t.Fatal(err)
				}

				return src, mockFile(t, filepath.Join(dir, "blob.blob.meta"), mockDestinationData)
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "copy data")

				data, err := os.ReadFile(filepath.Join(dir, "blob.blob.meta"))
				assert.NoError(err)
				assert.Equal(mockDestinationData, data)

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "destination is a directory",
			mock: func(t *testing.T, dir string) (string, string) {
				dst := filepath.Join(dir, "blob.blob.meta")
				if err := os.Mkdir(dst, 0o700); err != nil {
					t.Fatal(err)
				}
				mockFile(t, filepath.Join(dst, "original"), mockDestinationData)

				return mockFile(t, filepath.Join(t.TempDir(), "source"), mockBlobMetaData), dst
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "rename temp file")

				data, err := os.ReadFile(filepath.Join(dir, "blob.blob.meta", "original"))
				assert.NoError(err)
				assert.Equal(mockDestinationData, data)

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "missing destination directory",
			mock: func(t *testing.T, dir string) (string, string) {
				return mockFile(t, filepath.Join(t.TempDir(), "source"), mockBlobMetaData), filepath.Join(dir, "missing", "blob.blob.meta")
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create temp file")

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src, dst := tc.mock(t, dir)

			tc.expect(t, dir, copyFile(src, dst))
		})
	}
}

func TestHasNativeLayers(t *testing.T) {
	tests := []struct {
		name   string
		footer []byte
		mock   func(cs *mockContentStore)
		expect func(t *testing.T, cs *mockContentStore, native bool, err error)
	}{
		{
			name:   "chunked layer",
			footer: mockBlobFooter(nydus.NydusBlobFooterMagic, 0),
			mock:   func(cs *mockContentStore) {},
			expect: func(t *testing.T, cs *mockContentStore, native bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(native)
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
				}
			},
		},
		{
			name:   "native layer",
			footer: mockBlobFooter(nydus.NydusBlobFooterMagic, 1<<1),
			mock:   func(cs *mockContentStore) {},
			expect: func(t *testing.T, cs *mockContentStore, native bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(native)
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
				}
			},
		},
		{
			name:   "blob too small",
			footer: mockBlobFooter(nydus.NydusBlobFooterMagic, 0)[:32],
			mock:   func(cs *mockContentStore) {},
			expect: func(t *testing.T, cs *mockContentStore, native bool, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "too small")
				assert.False(native)
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
				}
			},
		},
		{
			name:   "bad footer magic",
			footer: mockBlobFooter("ODFOOTER", 0),
			mock:   func(cs *mockContentStore) {},
			expect: func(t *testing.T, cs *mockContentStore, native bool, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bad footer magic")
				assert.False(native)
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
				}
			},
		},
		{
			name:   "open blob failure",
			footer: mockBlobFooter(nydus.NydusBlobFooterMagic, 0),
			mock: func(cs *mockContentStore) {
				cs.openErr = errBlobReader
			},
			expect: func(t *testing.T, cs *mockContentStore, native bool, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errBlobReader)
				assert.False(native)
				assert.Empty(cs.readers)
			},
		},
		{
			name:   "read blob failure",
			footer: mockBlobFooter(nydus.NydusBlobFooterMagic, 0),
			mock: func(cs *mockContentStore) {
				cs.readErr = errBlobReader
			},
			expect: func(t *testing.T, cs *mockContentStore, native bool, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errBlobReader)
				assert.False(native)
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			cs := &mockContentStore{Store: store}
			tc.mock(cs)
			img := &Image{Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
				mockBootstrapLayer,
				mockBlob(t, store, nydus.MediaTypeNydusBlob, tc.footer),
			}}}
			native, err := HasNativeLayers(context.Background(), cs, img)

			tc.expect(t, cs, native, err)
		})
	}
}

func TestMaterializeBlobLayers(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, cs *mockContentStore, blobDir string) string
		expect func(t *testing.T, cs *mockContentStore, blobDir string, err error)
	}{
		{
			name: "write blob layers",
			mock: func(t *testing.T, cs *mockContentStore, blobDir string) string {
				return blobDir
			},
			expect: func(t *testing.T, cs *mockContentStore, blobDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				data, err := os.ReadFile(filepath.Join(blobDir, digest.FromBytes(mockBlobData).Encoded()))
				assert.NoError(err)
				assert.Equal(mockBlobData, data)

				entries, err := os.ReadDir(blobDir)
				assert.NoError(err)
				assert.Len(entries, 1)

				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
					_, err := r.ReaderAt.ReadAt(make([]byte, 1), 0)
					assert.Error(err)
					assert.NotErrorIs(err, io.EOF)
				}
			},
		},
		{
			name: "open blob failure",
			mock: func(t *testing.T, cs *mockContentStore, blobDir string) string {
				cs.openErr = errBlobReader
				return blobDir
			},
			expect: func(t *testing.T, cs *mockContentStore, blobDir string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errBlobReader)
				assert.Empty(cs.readers)
			},
		},
		{
			name: "read blob failure",
			mock: func(t *testing.T, cs *mockContentStore, blobDir string) string {
				cs.readErr = errBlobReader
				return blobDir
			},
			expect: func(t *testing.T, cs *mockContentStore, blobDir string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errBlobReader)
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
					_, err := r.ReaderAt.ReadAt(make([]byte, 1), 0)
					assert.Error(err)
					assert.NotErrorIs(err, io.EOF)
				}
			},
		},
		{
			name: "blob output blocked",
			mock: func(t *testing.T, cs *mockContentStore, blobDir string) string {
				if err := os.Mkdir(filepath.Join(blobDir, digest.FromBytes(mockBlobData).Encoded()), 0o700); err != nil {
					t.Fatal(err)
				}

				return blobDir
			},
			expect: func(t *testing.T, cs *mockContentStore, blobDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create blob")
				assert.Len(cs.readers, 1)
				for _, r := range cs.readers {
					assert.True(r.closed)
					_, err := r.ReaderAt.ReadAt(make([]byte, 1), 0)
					assert.Error(err)
					assert.NotErrorIs(err, io.EOF)
				}
			},
		},
		{
			name: "blob directory blocked",
			mock: func(t *testing.T, cs *mockContentStore, blobDir string) string {
				return mockFile(t, filepath.Join(blobDir, "not-a-directory"), nil)
			},
			expect: func(t *testing.T, cs *mockContentStore, blobDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create blob dir")
				assert.Empty(cs.readers)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			cs := &mockContentStore{Store: store}
			img := &Image{Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
				mockBootstrapLayer,
				mockBlob(t, store, nydus.MediaTypeNydusBlob, mockBlobData),
			}}}
			blobDir := tc.mock(t, cs, t.TempDir())
			err = MaterializeBlobLayers(context.Background(), cs, img, blobDir)

			tc.expect(t, cs, blobDir, err)
		})
	}
}
