/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFooter(t *testing.T) {
	assert := assert.New(t)
	_, err := readFooter(bytes.NewReader(nil), int64(len(mockChunkedBlob)))
	assert.ErrorContains(err, "read nydus footer")
}

func TestStageNydusMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, blob []byte, dir string) (ReaderAt, string)
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name: "reject bootstrap offset beyond blob",
			mock: func(t *testing.T, blob []byte, dir string) (ReaderAt, string) {
				binary.LittleEndian.PutUint64(blob[64+bootstrapOffsetField:], uint64(len(blob)+1))
				return bytes.NewReader(blob), dir
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid bootstrap offset")
			},
		},
		{
			name: "reject overflowing bootstrap offset",
			mock: func(t *testing.T, blob []byte, dir string) (ReaderAt, string) {
				binary.LittleEndian.PutUint64(blob[64+bootstrapOffsetField:], ^uint64(0))
				return bytes.NewReader(blob), dir
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid bootstrap offset")
			},
		},
		{
			name: "remove partial metadata when copy fails",
			mock: func(t *testing.T, blob []byte, dir string) (ReaderAt, string) {
				return mockReaderAt{Reader: bytes.NewReader(blob), dataEnd: 64}, dir
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stage nydus metadata")

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "remove temporary file when rename fails",
			mock: func(t *testing.T, blob []byte, dir string) (ReaderAt, string) {
				if err := os.Mkdir(filepath.Join(dir, "blob"), 0o700); err != nil {
					t.Fatal(err)
				}

				return bytes.NewReader(blob), dir
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "rename staged blob")

				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Len(entries, 1)
				assert.DirExists(filepath.Join(dir, "blob"))
			},
		},
		{
			name: "reject missing stage dir",
			mock: func(t *testing.T, blob []byte, dir string) (ReaderAt, string) {
				return bytes.NewReader(blob), filepath.Join(dir, "missing")
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create stage temp file")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ra, stageDir := tc.mock(t, bytes.Clone(mockChunkedBlob), dir)
			_, err := StageNydusMetadata(ra, int64(len(mockChunkedBlob)), "blob", stageDir)

			tc.expect(t, dir, err)
		})
	}
}

func TestIsRawDeviceBlob(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(blob []byte) ReaderAt
		expect func(t *testing.T, raw bool, err error)
	}{
		{
			name: "reject bad footer magic",
			mock: func(blob []byte) ReaderAt {
				blob[64] = 0
				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, raw bool, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bad footer magic")
				assert.False(raw)
			},
		},
		{
			name: "reject unsupported incompat features",
			mock: func(blob []byte) ReaderAt {
				binary.LittleEndian.PutUint32(blob[64+footerIncompatField:], 1<<31)
				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, raw bool, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported")
				assert.False(raw)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := IsRawDeviceBlob(tc.mock(bytes.Clone(mockChunkedBlob)), int64(len(mockChunkedBlob)))

			tc.expect(t, raw, err)
		})
	}
}

func TestExtractBlobMeta(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(blob []byte) ReaderAt
		expect func(t *testing.T, meta []byte, err error)
	}{
		{
			name: "reject bad footer magic",
			mock: func(blob []byte) ReaderAt {
				blob[64] = 0
				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, meta []byte, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bad footer magic")
				assert.Nil(meta)
			},
		},
		{
			name: "reject unsupported incompat features",
			mock: func(blob []byte) ReaderAt {
				binary.LittleEndian.PutUint32(blob[64+footerIncompatField:], 1<<31)
				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, meta []byte, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported")
				assert.Nil(meta)
			},
		},
		{
			name: "reject empty blob meta region",
			mock: func(blob []byte) ReaderAt {
				binary.LittleEndian.PutUint64(blob[64+blobMetaOffsetField:], 0)
				binary.LittleEndian.PutUint64(blob[64+blobMetaSizeField:], 0)

				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, meta []byte, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid blob meta region")
			},
		},
		{
			name: "reject blob meta region beyond blob",
			mock: func(blob []byte) ReaderAt {
				binary.LittleEndian.PutUint64(blob[64+blobMetaOffsetField:], uint64(len(blob)))
				binary.LittleEndian.PutUint64(blob[64+blobMetaSizeField:], 1)

				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, meta []byte, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid blob meta region")
			},
		},
		{
			name: "reject overflowing blob meta region",
			mock: func(blob []byte) ReaderAt {
				binary.LittleEndian.PutUint64(blob[64+blobMetaOffsetField:], ^uint64(0))
				binary.LittleEndian.PutUint64(blob[64+blobMetaSizeField:], 1)

				return bytes.NewReader(blob)
			},
			expect: func(t *testing.T, meta []byte, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid blob meta region")
			},
		},
		{
			name: "fail to read blob meta region",
			mock: func(blob []byte) ReaderAt {
				return mockReaderAt{Reader: bytes.NewReader(blob), dataEnd: 64}
			},
			expect: func(t *testing.T, meta []byte, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read blob meta region")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta, err := ExtractBlobMeta(tc.mock(bytes.Clone(mockChunkedBlob)), int64(len(mockChunkedBlob)))

			tc.expect(t, meta, err)
		})
	}
}
