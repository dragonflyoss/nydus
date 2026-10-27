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

	"github.com/stretchr/testify/require"
)

func TestFooterValidationAndStagingCleanup(t *testing.T) {
	blob := make([]byte, 64+NydusBlobFooterSize)
	footer := blob[64:]
	copy(footer, NydusBlobFooterMagic)
	binary.LittleEndian.PutUint64(footer[bootstrapOffsetField:], 16)
	binary.LittleEndian.PutUint64(footer[blobMetaOffsetField:], 32)
	binary.LittleEndian.PutUint64(footer[blobMetaSizeField:], 4)
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{"magic", func(f []byte) { f[0] = 0 }, "bad footer magic"},
		{"unsupported-feature", func(f []byte) { binary.LittleEndian.PutUint32(f[footerIncompatField:], 1<<31) }, "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Clone(blob)
			tc.mutate(data[64:])
			raw, err := IsRawDeviceBlob(bytes.NewReader(data), int64(len(data)))
			require.ErrorContains(t, err, tc.want)
			require.False(t, raw)
			meta, err := ExtractBlobMeta(bytes.NewReader(data), int64(len(data)))
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, meta)
		})
	}
	_, err := readFooter(bytes.NewReader(nil), int64(len(blob)))
	require.ErrorContains(t, err, "read nydus footer")
	for _, offset := range []uint64{uint64(len(blob) + 1), ^uint64(0)} {
		data := bytes.Clone(blob)
		binary.LittleEndian.PutUint64(data[64+bootstrapOffsetField:], offset)
		_, err := StageNydusMetadata(bytes.NewReader(data), int64(len(data)), "blob", t.TempDir())
		require.ErrorContains(t, err, "invalid bootstrap offset")
	}
	for _, region := range [][2]uint64{{0, 0}, {uint64(len(blob)), 1}, {^uint64(0), 1}} {
		data := bytes.Clone(blob)
		binary.LittleEndian.PutUint64(data[64+blobMetaOffsetField:], region[0])
		binary.LittleEndian.PutUint64(data[64+blobMetaSizeField:], region[1])
		_, err := ExtractBlobMeta(bytes.NewReader(data), int64(len(data)))
		require.ErrorContains(t, err, "invalid blob meta region")
	}
	reader := metadataOnlyReader{bytes.NewReader(blob), 64}
	_, err = ExtractBlobMeta(reader, int64(len(blob)))
	require.ErrorContains(t, err, "read blob meta region")
	work := t.TempDir()
	_, err = StageNydusMetadata(reader, int64(len(blob)), "blob", work)
	require.ErrorContains(t, err, "stage nydus metadata")
	entries, err := os.ReadDir(work)
	require.NoError(t, err)
	require.Empty(t, entries, "failed copies must not leave partial metadata")
	require.NoError(t, os.Mkdir(filepath.Join(work, "blob"), 0o700))
	_, err = StageNydusMetadata(bytes.NewReader(blob), int64(len(blob)), "blob", work)
	require.ErrorContains(t, err, "rename staged blob")
	entries, err = os.ReadDir(work)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "blob", entries[0].Name(), "failed rename must remove its temporary file")
	_, err = StageNydusMetadata(bytes.NewReader(blob), int64(len(blob)), "blob", filepath.Join(work, "missing"))
	require.ErrorContains(t, err, "create stage temp file")
}
