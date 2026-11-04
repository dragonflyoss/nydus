/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildOption_args(t *testing.T) {
	tests := []struct {
		name   string
		opt    BuildOption
		expect func(t *testing.T, args []string, err error)
	}{
		{
			name: "default layout",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", DefaultCompressor, "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "none layout",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: "none"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", "none", "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "zstd layout from directory",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: "zstd", SourceType: "dir"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", "zstd", "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "lz4 layout from tar",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: "lz4", SourceType: "tar"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "tar", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", "lz4", "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "erofs-none layout",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: "erofs-none"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", "erofs-none", "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "erofs-lz4 layout from directory",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: "erofs-lz4", SourceType: "dir"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", "erofs-lz4", "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "erofs-zstd layout from tar",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: "erofs-zstd", SourceType: "tar"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "tar", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", "erofs-zstd", "--log-level", DefaultLogLevel}, args)
			},
		},
		{
			name: "forward directory exclusions",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Excludes: []string{"secret", "cache"}},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", strconv.Itoa(DefaultChunkSize), "--compressor", DefaultCompressor, "--log-level", DefaultLogLevel, "--exclude", "secret", "--exclude", "cache"}, args)
			},
		},
		{
			name: "explicit log level and chunk size",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", ChunkSize: 1 << 20, LogLevel: "debug"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", "1048576", "--compressor", DefaultCompressor, "--log-level", "debug"}, args)
			},
		},
		{
			name: "reject unsupported source type",
			opt:  BuildOption{SourceType: "invalid"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `unsupported build source type "invalid"`)
				assert.Nil(args)
			},
		},
		{
			name: "reject tar exclusions",
			opt:  BuildOption{SourceType: "tar", Excludes: []string{"secret"}},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "tar sources do not support path exclusions")
				assert.Nil(args)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := tc.opt.args()

			tc.expect(t, args, err)
		})
	}
}

func TestRunNydusBuild(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		opt    BuildOption
		expect func(t *testing.T, blobPath string, err error)
	}{
		{
			name: "stream stdin source into blob",
			body: "test \"$type\" = tar\ncat \"$source\" > \"$blob\"\n",
			opt:  BuildOption{SourceDir: "/dev/stdin", SourceType: "tar", Stdin: strings.NewReader("layer tar")},
			expect: func(t *testing.T, blobPath string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				data, err := os.ReadFile(blobPath)
				assert.NoError(err)
				assert.Equal("layer tar", string(data))
			},
		},
		{
			name: "invalid options do not run the builder",
			body: ": > \"$blob\"\n",
			opt:  BuildOption{SourceDir: "source", SourceType: "tar", Excludes: []string{"secret"}},
			expect: func(t *testing.T, blobPath string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "tar sources do not support path exclusions")
				assert.NoFileExists(blobPath)
			},
		},
		{
			name: "builder failure carries stderr",
			body: "echo invalid source >&2\nexit 3\n",
			opt:  BuildOption{SourceDir: "source"},
			expect: func(t *testing.T, blobPath string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus build: invalid source")
				assert.ErrorContains(err, "exit status 3")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opt.BuilderPath = mockBuilder(t, tc.body)
			tc.opt.BlobPath = filepath.Join(t.TempDir(), "blob")

			tc.expect(t, tc.opt.BlobPath, RunNydusBuild(context.Background(), tc.opt))
		})
	}
}

func TestRunNydusExport(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		expect func(t *testing.T, output string, err error)
	}{
		{
			name: "stream exported tar to destination",
			body: "test -f \"$source\"\nprintf 'exported tar'\n",
			expect: func(t *testing.T, output string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("exported tar", output)
			},
		},
		{
			name: "builder failure carries stderr",
			body: "echo corrupt blob >&2\nexit 1\n",
			expect: func(t *testing.T, output string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus export: corrupt blob")
				assert.Empty(output)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blobPath := filepath.Join(t.TempDir(), "blob")
			if err := os.WriteFile(blobPath, []byte("blob"), 0o600); err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			err := RunNydusExport(context.Background(), ExportOption{BuilderPath: mockBuilder(t, tc.body), BlobPath: blobPath}, &output)

			tc.expect(t, output.String(), err)
		})
	}
}
