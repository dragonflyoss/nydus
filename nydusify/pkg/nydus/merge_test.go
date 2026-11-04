/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
)

var (
	mockChunkedBlob = mockBlob(0, 4)

	mockNativeBlob = mockBlob(footerFlagRawDevice, 0)

	mockInvalidMetaBlob = mockBlob(0, 0)

	mockAppendFiles = []AppendFile{{Name: "extra", Data: []byte("appended metadata")}}
)

type mockReaderAt struct {
	*bytes.Reader
	dataEnd int64
}

func (r mockReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < r.dataEnd {
		return 0, errors.New("merge must not read the blob data region")
	}

	return r.Reader.ReadAt(p, off)
}

func builderPath(t *testing.T) string {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run SDK build/merge integrations")
	}

	return builder
}

func mockBlob(incompat uint32, metaSize uint64) []byte {
	blob := make([]byte, 64+NydusBlobFooterSize)
	copy(blob[32:], "meta")
	footer := blob[64:]
	copy(footer, NydusBlobFooterMagic)
	binary.LittleEndian.PutUint32(footer[footerIncompatField:], incompat)
	binary.LittleEndian.PutUint64(footer[bootstrapOffsetField:], 16)
	binary.LittleEndian.PutUint64(footer[blobMetaOffsetField:], 32)
	binary.LittleEndian.PutUint64(footer[blobMetaSizeField:], metaSize)

	return blob
}

func mockLayers(t *testing.T, workDir, compressor string) ([]Layer, map[string][]byte) {
	builder := builderPath(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var layers []Layer
	metas := make(map[string][]byte)
	for _, name := range []string{"lower", "upper"} {
		source := t.TempDir()
		if err := os.WriteFile(filepath.Join(source, name), []byte(name+" payload"), 0o644); err != nil {
			t.Fatal(err)
		}

		var blob bytes.Buffer
		if err := BuildBlob(ctx, &blob, source, PackOption{BuilderPath: builder, WorkDir: workDir, Compressor: compressor}); err != nil {
			t.Fatal(err)
		}

		dgst := digest.FromBytes(blob.Bytes())
		footer := blob.Bytes()[blob.Len()-NydusBlobFooterSize:]
		layers = append(layers, Layer{Digest: dgst, ReaderAt: mockReaderAt{Reader: bytes.NewReader(blob.Bytes()), dataEnd: int64(binary.LittleEndian.Uint64(footer[bootstrapOffsetField:]))}})
		if size := binary.LittleEndian.Uint64(footer[blobMetaSizeField:]); size > 0 {
			offset := binary.LittleEndian.Uint64(footer[blobMetaOffsetField:])
			metas["image/"+dgst.Encoded()+".blob.meta"] = blob.Bytes()[offset : offset+size]
		}
	}

	return layers, metas
}

func mockUntar(t *testing.T, data []byte) map[string][]byte {
	files := make(map[string][]byte)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		assert.NotContains(t, files, header.Name)
		if files[header.Name], err = io.ReadAll(tr); err != nil {
			t.Fatal(err)
		}
	}

	return files
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name   string
		layers func(t *testing.T, workDir string) ([]Layer, map[string][]byte)
		expect func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte)
	}{
		{
			name: "merge chunked layers",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "zstd")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				builder := builderPath(t)
				var output bytes.Buffer
				digests, err := Merge(context.Background(), layers, &output, MergeOption{BuilderPath: builder, WorkDir: workDir, AppendFiles: mockAppendFiles})
				assert.NoError(err)
				assert.Equal([]digest.Digest{layers[0].Digest, layers[1].Digest}, digests)

				files := mockUntar(t, output.Bytes())
				assert.NotEmpty(files[BootstrapFileNameInLayer])
				bootstrapPath := filepath.Join(t.TempDir(), "bootstrap")
				if err := os.WriteFile(bootstrapPath, files[BootstrapFileNameInLayer], 0o600); err != nil {
					t.Fatal(err)
				}

				assert.NoError(exec.Command(builder, "check", "--bootstrap", bootstrapPath).Run())

				delete(files, BootstrapFileNameInLayer)
				expected := map[string][]byte{"image/extra": []byte("appended metadata")}
				maps.Copy(expected, metas)
				assert.Equal(expected, files)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "merge native layers",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "erofs-lz4")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				builder := builderPath(t)
				var output bytes.Buffer
				digests, err := Merge(context.Background(), layers, &output, MergeOption{BuilderPath: builder, WorkDir: workDir, AppendFiles: mockAppendFiles})
				assert.NoError(err)
				assert.Equal([]digest.Digest{layers[0].Digest, layers[1].Digest}, digests)

				files := mockUntar(t, output.Bytes())
				assert.NotEmpty(files[BootstrapFileNameInLayer])
				bootstrapPath := filepath.Join(t.TempDir(), "bootstrap")
				if err := os.WriteFile(bootstrapPath, files[BootstrapFileNameInLayer], 0o600); err != nil {
					t.Fatal(err)
				}

				assert.NoError(exec.Command(builder, "check", "--bootstrap", bootstrapPath).Run())

				delete(files, BootstrapFileNameInLayer)
				assert.Equal(map[string][]byte{"image/extra": []byte("appended metadata")}, files)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "fail to write chunked bootstrap tar",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "zstd")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				_, err := Merge(context.Background(), layers, &mockWriter{}, MergeOption{BuilderPath: builderPath(t), WorkDir: workDir, AppendFiles: mockAppendFiles})
				assert.ErrorIs(err, errMockWrite)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "fail to write native bootstrap tar",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "erofs-lz4")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				_, err := Merge(context.Background(), layers, &mockWriter{}, MergeOption{BuilderPath: builderPath(t), WorkDir: workDir, AppendFiles: mockAppendFiles})
				assert.ErrorIs(err, errMockWrite)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "fail to close chunked bootstrap tar",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "zstd")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				opt := MergeOption{BuilderPath: builderPath(t), WorkDir: workDir, AppendFiles: mockAppendFiles}
				var output bytes.Buffer
				if _, err := Merge(context.Background(), layers, &output, opt); err != nil {
					t.Fatal(err)
				}

				_, err := Merge(context.Background(), layers, &mockWriter{remaining: output.Len() - 1}, opt)
				assert.ErrorIs(err, errMockWrite)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "fail to close native bootstrap tar",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "erofs-lz4")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				opt := MergeOption{BuilderPath: builderPath(t), WorkDir: workDir, AppendFiles: mockAppendFiles}
				var output bytes.Buffer
				if _, err := Merge(context.Background(), layers, &output, opt); err != nil {
					t.Fatal(err)
				}

				_, err := Merge(context.Background(), layers, &mockWriter{remaining: output.Len() - 1}, opt)
				assert.ErrorIs(err, errMockWrite)

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "merge chunked layers without builder",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "zstd")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				var output bytes.Buffer
				digests, err := Merge(context.Background(), layers, &output, MergeOption{BuilderPath: filepath.Join(t.TempDir(), "missing-builder"), WorkDir: workDir, AppendFiles: mockAppendFiles})
				assert.ErrorContains(err, "nydus merge")
				assert.Nil(digests)
				assert.Zero(output.Len())

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "merge native layers without builder",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return mockLayers(t, workDir, "erofs-lz4")
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				var output bytes.Buffer
				digests, err := Merge(context.Background(), layers, &output, MergeOption{BuilderPath: filepath.Join(t.TempDir(), "missing-builder"), WorkDir: workDir, AppendFiles: mockAppendFiles})
				assert.ErrorContains(err, "nydus merge")
				assert.Nil(digests)
				assert.Zero(output.Len())

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "reject empty layers",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return nil, nil
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				var output bytes.Buffer
				digests, err := Merge(context.Background(), layers, &output, MergeOption{WorkDir: workDir})
				assert.ErrorContains(err, "no layers to merge")
				assert.Nil(digests)
				assert.Zero(output.Len())

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "reject invalid blob",
			layers: func(t *testing.T, workDir string) ([]Layer, map[string][]byte) {
				return []Layer{{Digest: digest.FromString("bad"), ReaderAt: bytes.NewReader([]byte("not a blob"))}}, nil
			},
			expect: func(t *testing.T, workDir string, layers []Layer, metas map[string][]byte) {
				assert := assert.New(t)
				var output bytes.Buffer
				digests, err := Merge(context.Background(), layers, &output, MergeOption{WorkDir: workDir})
				assert.ErrorContains(err, "stage blob "+digest.FromString("bad").String())
				assert.Nil(digests)
				assert.Zero(output.Len())

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			layers, metas := tc.layers(t, workDir)

			tc.expect(t, workDir, layers, metas)
		})
	}
}

func TestMergeBootstrap(t *testing.T) {
	tests := []struct {
		name           string
		blob           []byte
		body           string
		missingWorkDir bool
		expect         func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error)
	}{
		{
			name: "merge staged blob and return blob meta",
			blob: mockChunkedBlob,
			body: "test \"$(basename \"$source\")\" = " + digest.FromBytes(mockChunkedBlob).Encoded() + "\nprintf merged > \"$(dirname \"$source\")/bootstrap\"\n",
			expect: func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("merged", string(bootstrap))
				assert.Equal([]BlobMetaFile{{Name: dgst.Encoded() + ".blob.meta", Data: []byte("meta")}}, metas)
				assert.Empty(entries)
			},
		},
		{
			name: "native layer has no blob meta",
			blob: mockNativeBlob,
			body: "printf merged > \"$(dirname \"$source\")/bootstrap\"\n",
			expect: func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("merged", string(bootstrap))
				assert.Empty(metas)
				assert.Empty(entries)
			},
		},
		{
			name:           "missing work dir",
			blob:           mockChunkedBlob,
			missingWorkDir: true,
			expect: func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create merge scratch dir")
				assert.Nil(bootstrap)
				assert.Empty(entries)
			},
		},
		{
			name: "invalid blob meta region",
			blob: mockInvalidMetaBlob,
			body: "printf merged > \"$(dirname \"$source\")/bootstrap\"\n",
			expect: func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "extract blob meta "+dgst.String())
				assert.ErrorContains(err, "invalid blob meta region")
				assert.Nil(bootstrap)
				assert.Empty(entries)
			},
		},
		{
			name: "builder writes no bootstrap",
			blob: mockChunkedBlob,
			body: "exit 0\n",
			expect: func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read bootstrap")
				assert.Nil(bootstrap)
				assert.Nil(metas)
				assert.Empty(entries)
			},
		},
		{
			name: "builder failure carries stderr",
			blob: mockChunkedBlob,
			body: "echo merge rejected >&2\nexit 2\n",
			expect: func(t *testing.T, dgst digest.Digest, bootstrap []byte, metas []BlobMetaFile, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus merge: merge rejected")
				assert.Nil(bootstrap)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scratch := t.TempDir()
			workDir := scratch
			if tc.missingWorkDir {
				workDir = filepath.Join(scratch, "missing")
			}

			dgst := digest.FromBytes(tc.blob)
			bootstrap, metas, mergeErr := MergeBootstrap(context.Background(), []Layer{{Digest: dgst, ReaderAt: bytes.NewReader(tc.blob)}}, MergeOption{BuilderPath: mockBuilder(t, tc.body), WorkDir: workDir})
			entries, err := os.ReadDir(scratch)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, dgst, bootstrap, metas, entries, mergeErr)
		})
	}
}
