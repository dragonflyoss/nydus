/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
)

func mockBuilder(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "builder")
	script := "#!/bin/sh\nset -eu\nshift\nsource=$1\nshift\nblob=\ntype=\nwhile [ $# -gt 0 ]; do\ncase $1 in\n--blob) blob=$2;;\n--source-type) type=$2;;\nesac\nshift 2\ndone\n" + body
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestPack(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		expect func(t *testing.T, ctx context.Context, opt PackOption)
	}{
		{
			name: "reject canceled context",
			expect: func(t *testing.T, ctx context.Context, opt PackOption) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				writer, err := Pack(ctx, io.Discard, opt)
				assert.ErrorIs(err, context.Canceled)
				assert.Nil(writer)
			},
		},
		{
			name: "stream tar without extraction",
			body: "test \"$type\" = tar\ncat \"$source\" > \"$blob\"\n",
			expect: func(t *testing.T, ctx context.Context, opt PackOption) {
				assert := assert.New(t)
				var output bytes.Buffer
				writer, err := Pack(ctx, &output, opt)
				if err != nil {
					t.Fatal(err)
				}

				payload := bytes.Repeat([]byte("tar-bytes"), 20000)
				_, err = writer.Write(payload)
				assert.NoError(err)
				assert.NoError(writer.Close())
				assert.Equal(payload, output.Bytes())
				assert.NoError(writer.Close())

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "unblock input when builder exits early",
			body: "echo rejected >&2\nexit 7\n",
			expect: func(t *testing.T, ctx context.Context, opt PackOption) {
				assert := assert.New(t)
				writer, err := Pack(ctx, io.Discard, opt)
				if err != nil {
					t.Fatal(err)
				}

				var writeErr error
				for range 64 {
					if _, writeErr = writer.Write(make([]byte, 1<<20)); writeErr != nil {
						break
					}
				}

				assert.Error(writeErr)
				assert.ErrorContains(writer.Close(), "rejected")
				assert.NoError(ctx.Err())
			},
		},
		{
			name: "stop on destination failure",
			body: "exec cat \"$source\" > \"$blob\"\n",
			expect: func(t *testing.T, ctx context.Context, opt PackOption) {
				assert := assert.New(t)
				writer, err := Pack(ctx, &mockWriter{}, opt)
				if err != nil {
					t.Fatal(err)
				}

				_, _ = writer.Write(make([]byte, 1<<20))
				assert.ErrorIs(writer.Close(), errMockWrite)
				assert.NoError(ctx.Err())
			},
		},
		{
			name: "unblock input on cancellation",
			body: "exec cat \"$source\" > \"$blob\"\n",
			expect: func(t *testing.T, ctx context.Context, opt PackOption) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(ctx)
				writer, err := Pack(ctx, io.Discard, opt)
				if err != nil {
					t.Fatal(err)
				}

				cancel()
				_, err = writer.Write([]byte("x"))
				assert.Error(err)
				assert.Error(writer.Close())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			tc.expect(t, ctx, PackOption{BuilderPath: mockBuilder(t, tc.body), WorkDir: t.TempDir()})
		})
	}
}

func TestBuildBlob(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, ctx context.Context, source, workDir string)
	}{
		{
			name: "build chunked layout",
			expect: func(t *testing.T, ctx context.Context, source, workDir string) {
				assert := assert.New(t)
				builder := builderPath(t)
				var blob bytes.Buffer
				if err := BuildBlob(ctx, &blob, source, PackOption{BuilderPath: builder, WorkDir: workDir, Compressor: "zstd"}); err != nil {
					t.Fatal(err)
				}

				blobPath := filepath.Join(t.TempDir(), digest.FromBytes(blob.Bytes()).Encoded())
				if err := os.WriteFile(blobPath, blob.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}

				var exported bytes.Buffer
				if err := RunNydusExport(ctx, ExportOption{BuilderPath: builder, BlobPath: blobPath}, &exported); err != nil {
					t.Fatal(err)
				}

				footer := blob.Bytes()[blob.Len()-NydusBlobFooterSize:]
				assert.Equal([]byte("lower payload"), mockUntar(t, exported.Bytes())["lower"])
				assert.Positive(binary.LittleEndian.Uint64(footer[bootstrapOffsetField:]))
				assert.Positive(binary.LittleEndian.Uint64(footer[blobMetaSizeField:]))
			},
		},
		{
			name: "build native layout",
			expect: func(t *testing.T, ctx context.Context, source, workDir string) {
				assert := assert.New(t)
				builder := builderPath(t)
				var blob bytes.Buffer
				if err := BuildBlob(ctx, &blob, source, PackOption{BuilderPath: builder, WorkDir: workDir, Compressor: "erofs-lz4"}); err != nil {
					t.Fatal(err)
				}

				blobPath := filepath.Join(t.TempDir(), digest.FromBytes(blob.Bytes()).Encoded())
				if err := os.WriteFile(blobPath, blob.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}

				var exported bytes.Buffer
				if err := RunNydusExport(ctx, ExportOption{BuilderPath: builder, BlobPath: blobPath}, &exported); err != nil {
					t.Fatal(err)
				}

				footer := blob.Bytes()[blob.Len()-NydusBlobFooterSize:]
				assert.Equal([]byte("lower payload"), mockUntar(t, exported.Bytes())["lower"])
				assert.Positive(binary.LittleEndian.Uint64(footer[bootstrapOffsetField:]))
			},
		},
		{
			name: "reject missing work dir",
			expect: func(t *testing.T, ctx context.Context, source, workDir string) {
				assert := assert.New(t)
				assert.ErrorContains(BuildBlob(ctx, io.Discard, source, PackOption{WorkDir: filepath.Join(workDir, "missing")}), "create fifo dir")
			},
		},
		{
			name: "stop builder on destination failure",
			expect: func(t *testing.T, ctx context.Context, source, workDir string) {
				assert := assert.New(t)
				err := BuildBlob(ctx, &mockWriter{}, source, PackOption{BuilderPath: mockBuilder(t, "test \"$type\" = dir\nexec cat /dev/zero > \"$blob\"\n"), WorkDir: workDir})
				assert.ErrorIs(err, errMockWrite)
				assert.NoError(ctx.Err())

				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "lower"), []byte("lower payload"), 0o644); err != nil {
				t.Fatal(err)
			}

			tc.expect(t, ctx, source, t.TempDir())
		})
	}
}

func TestOpenFifoRead(t *testing.T) {
	assert := assert.New(t)
	file, err := openFifoRead(filepath.Join(t.TempDir(), "missing"))
	assert.ErrorIs(err, os.ErrNotExist)
	assert.Nil(file)
}
