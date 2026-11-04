/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	errMockWrite = errors.New("mock write failed")

	mockBlobMetas = []BlobMetaFile{{Name: "blob.blob.meta", Data: []byte("m")}}
)

type mockWriter struct {
	remaining int
}

func (w *mockWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errMockWrite
	}

	w.remaining -= len(p)
	return len(p), nil
}

type mockReader struct {
	largest int
}

func (r *mockReader) Read(p []byte) (int, error) {
	r.largest = max(r.largest, len(p))
	clear(p)

	return len(p), nil
}

func TestWriteBootstrapTarFromReader(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T)
	}{
		{
			name: "fail to write bootstrap dir header",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				err := WriteBootstrapTarFromReader(tar.NewWriter(&mockWriter{}), strings.NewReader(""), 0, mockBlobMetas, mockAppendFiles)
				assert.ErrorIs(err, errMockWrite)
				assert.ErrorContains(err, "bootstrap dir header")
			},
		},
		{
			name: "fail to write bootstrap file header",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				err := WriteBootstrapTarFromReader(tar.NewWriter(&mockWriter{remaining: 512}), strings.NewReader(""), 0, mockBlobMetas, mockAppendFiles)
				assert.ErrorIs(err, errMockWrite)
				assert.ErrorContains(err, "bootstrap file header")
			},
		},
		{
			name: "fail to write blob meta header",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				err := WriteBootstrapTarFromReader(tar.NewWriter(&mockWriter{remaining: 1024}), strings.NewReader(""), 0, mockBlobMetas, mockAppendFiles)
				assert.ErrorIs(err, errMockWrite)
				assert.ErrorContains(err, "blob meta header")
			},
		},
		{
			name: "fail to write blob meta",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				err := WriteBootstrapTarFromReader(tar.NewWriter(&mockWriter{remaining: 1536}), strings.NewReader(""), 0, mockBlobMetas, mockAppendFiles)
				assert.ErrorIs(err, errMockWrite)
				assert.ErrorContains(err, "write blob meta")
			},
		},
		{
			name: "fail to write appended file header",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				err := WriteBootstrapTarFromReader(tar.NewWriter(&mockWriter{remaining: 2048}), strings.NewReader(""), 0, mockBlobMetas, mockAppendFiles)
				assert.ErrorIs(err, errMockWrite)
				assert.ErrorContains(err, "appended file header")
			},
		},
		{
			name: "fail to write appended file",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				err := WriteBootstrapTarFromReader(tar.NewWriter(&mockWriter{remaining: 2560}), strings.NewReader(""), 0, mockBlobMetas, mockAppendFiles)
				assert.ErrorIs(err, errMockWrite)
				assert.ErrorContains(err, "write appended file")
			},
		},
		{
			name: "reject negative bootstrap size",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				assert.ErrorContains(WriteBootstrapTarFromReader(tar.NewWriter(io.Discard), strings.NewReader(""), -1, nil, nil), "bootstrap file header")
			},
		},
		{
			name: "stream bootstrap in bounded reads",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				var archive bytes.Buffer
				tw := tar.NewWriter(&archive)
				bootstrap := &mockReader{}
				assert.NoError(WriteBootstrapTarFromReader(tw, bootstrap, 2<<20, nil, nil))
				assert.NoError(tw.Close())
				assert.LessOrEqual(bootstrap.largest, 32*1024)

				files := mockUntar(t, archive.Bytes())
				assert.Len(files, 1)
				assert.Len(files[BootstrapFileNameInLayer], 2<<20)
			},
		},
		{
			name: "reject short bootstrap",
			expect: func(t *testing.T) {
				assert := assert.New(t)
				assert.Error(WriteBootstrapTarFromReader(tar.NewWriter(io.Discard), strings.NewReader("short"), 100, nil, nil))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t)
		})
	}
}
