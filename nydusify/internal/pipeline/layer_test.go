/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockPAXModTime = time.Unix(1700000001, 123456789)

	mockPAXFiles = map[string][]byte{
		"small":       []byte("hello"),
		"large":       bytes.Repeat([]byte("payload"), 45000),
		".wh.removed": {},
	}
)

func mockPAXTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"small", "large", ".wh.removed"} {
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Mode:    0o640,
			Uid:     1234,
			Gid:     5678,
			Size:    int64(len(mockPAXFiles[name])),
			ModTime: mockPAXModTime,
			Format:  tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(mockPAXFiles[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "device", Typeflag: tar.TypeChar, Mode: 0o600, Devmajor: 1, Devminor: 3}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestLayerConvertFunc(t *testing.T) {
	tests := []struct {
		name     string
		canceled bool
		desc     ocispec.Descriptor
		expect   func(t *testing.T, desc *ocispec.Descriptor, err error)
	}{
		{
			name:     "reject canceled context",
			canceled: true,
			desc:     mockGzipLayer,
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Nil(desc)
			},
		},
		{
			name: "skip image config",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: mockGzipLayer.Digest},
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "skip nydus blob",
			desc: ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: mockGzipLayer.Digest},
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "skip nydus bootstrap",
			desc: mockBootstrapLayer,
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "wrap layer conversion error",
			desc: mockGzipLayer,
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert layer "+mockGzipLayer.Digest.String())
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			desc, err := LayerConvertFunc(nydus.PackOption{BuilderPath: "/nonexistent/nydus", WorkDir: t.TempDir()})(ctx, mockStore(t), tc.desc)

			tc.expect(t, desc, err)
		})
	}
}

func TestLayerConvertConcurrency(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		expect func(t *testing.T, concurrency int)
	}{
		{
			name: "use positive override",
			env:  "3",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.Equal(3, concurrency)
			},
		},
		{
			name: "default without override",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.GreaterOrEqual(concurrency, 2)
				assert.LessOrEqual(concurrency, 4)
			},
		},
		{
			name: "ignore zero override",
			env:  "0",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.GreaterOrEqual(concurrency, 2)
				assert.LessOrEqual(concurrency, 4)
			},
		},
		{
			name: "ignore invalid override",
			env:  "many",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.GreaterOrEqual(concurrency, 2)
				assert.LessOrEqual(concurrency, 4)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NYDUSIFY_LAYER_CONCURRENCY", tc.env)

			tc.expect(t, layerConvertConcurrency())
		})
	}
}

func TestConvertLayer(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run real builder conversion tests")
	}

	expectExported := func(t *testing.T, ctx context.Context, cs content.Store, opt nydus.PackOption, desc *ocispec.Descriptor, err error) {
		assert := assert.New(t)
		assert.NoError(err)

		blob, err := content.ReadBlob(ctx, cs, *desc)
		assert.NoError(err)
		meta, err := nydus.ExtractBlobMeta(bytes.NewReader(blob), int64(len(blob)))
		assert.NoError(err)
		if strings.HasPrefix(opt.Compressor, "erofs-") {
			assert.Nil(meta)
		} else {
			var header struct {
				Magic    [8]byte
				_        uint32
				Features uint32
			}
			assert.NoError(binary.Read(bytes.NewReader(meta), binary.LittleEndian, &header))
			assert.Equal("NDBLMETA", string(header.Magic[:]))
			assert.Zero(header.Features)
			assert.GreaterOrEqual(len(meta), 24)
		}

		staged, err := nydus.StageNydusMetadata(bytes.NewReader(blob), int64(len(blob)), desc.Digest.Encoded(), t.TempDir())
		assert.NoError(err)
		bootstrap := filepath.Join(t.TempDir(), "bootstrap")
		assert.NoError(nydus.RunNydusMerge(ctx, nydus.MergeBuildOption{BuilderPath: opt.BuilderPath, SourcePaths: []string{staged}, BootstrapPath: bootstrap}))
		assert.NoError(exec.CommandContext(ctx, opt.BuilderPath, "check", "--bootstrap", bootstrap).Run())
		bootstrapData, err := os.ReadFile(bootstrap)
		assert.NoError(err)

		var bundle bytes.Buffer
		bundleWriter := tar.NewWriter(&bundle)
		metaName := "image/" + desc.Digest.Encoded() + ".blob.meta"
		assert.NoError(nydus.WriteBootstrapTar(bundleWriter, bootstrapData, []nydus.BlobMetaFile{{Name: filepath.Base(metaName), Data: meta}}, nil))
		assert.NoError(bundleWriter.Close())
		bundled := map[string]string{}
		bundleReader := tar.NewReader(&bundle)
		for {
			hdr, err := bundleReader.Next()
			if err != nil {
				assert.ErrorIs(err, io.EOF)
				break
			}

			data, err := io.ReadAll(bundleReader)
			assert.NoError(err)
			bundled[hdr.Name] = string(data)
		}
		assert.Contains(bundled, metaName)
		assert.Equal(string(meta), bundled[metaName])

		path := filepath.Join(t.TempDir(), desc.Digest.Encoded())
		assert.NoError(os.WriteFile(path, blob, 0o600))
		var exported bytes.Buffer
		assert.NoError(nydus.RunNydusExport(ctx, nydus.ExportOption{BuilderPath: opt.BuilderPath, BlobPath: path}, &exported))
		seen := map[string]bool{}
		exportReader := tar.NewReader(&exported)
		for {
			hdr, err := exportReader.Next()
			if err != nil {
				assert.ErrorIs(err, io.EOF)
				break
			}

			name := filepath.Clean(hdr.Name)
			if want, ok := mockPAXFiles[name]; ok {
				data, err := io.ReadAll(exportReader)
				assert.NoError(err)
				assert.Equal(want, data)
				assert.Equal(1234, hdr.Uid)
				assert.Equal(5678, hdr.Gid)
				assert.Equal(mockPAXModTime.UnixNano(), hdr.ModTime.UnixNano())
				seen[name] = true
			}
			if name == "device" {
				assert.Equal(byte(tar.TypeChar), hdr.Typeflag)
				assert.Equal(int64(1), hdr.Devmajor)
				assert.Equal(int64(3), hdr.Devminor)
				seen[name] = true
			}
		}
		assert.Equal(map[string]bool{"small": true, "large": true, ".wh.removed": true, "device": true}, seen)
	}

	expectRejected := func(t *testing.T, ctx context.Context, cs content.Store, opt nydus.PackOption, desc *ocispec.Descriptor, err error) {
		assert := assert.New(t)
		assert.Error(err)
		assert.Nil(desc)
		assert.NoError(ctx.Err())
	}

	tests := []struct {
		name       string
		mediaType  string
		data       func(t *testing.T) []byte
		compressor string
		expect     func(t *testing.T, ctx context.Context, cs content.Store, opt nydus.PackOption, desc *ocispec.Descriptor, err error)
	}{
		{
			name:       "convert layer with none compressor",
			mediaType:  ocispec.MediaTypeImageLayerGzip,
			data:       func(t *testing.T) []byte { return mockGzip(t, mockPAXTar(t)) },
			compressor: "none",
			expect:     expectExported,
		},
		{
			name:       "convert layer with zstd compressor",
			mediaType:  ocispec.MediaTypeImageLayerGzip,
			data:       func(t *testing.T) []byte { return mockGzip(t, mockPAXTar(t)) },
			compressor: "zstd",
			expect:     expectExported,
		},
		{
			name:       "convert layer with lz4 compressor",
			mediaType:  ocispec.MediaTypeImageLayerGzip,
			data:       func(t *testing.T) []byte { return mockGzip(t, mockPAXTar(t)) },
			compressor: "lz4",
			expect:     expectExported,
		},
		{
			name:       "convert layer to native erofs with none compressor",
			mediaType:  ocispec.MediaTypeImageLayerGzip,
			data:       func(t *testing.T) []byte { return mockGzip(t, mockPAXTar(t)) },
			compressor: "erofs-none",
			expect:     expectExported,
		},
		{
			name:       "convert layer to native erofs with lz4 compressor",
			mediaType:  ocispec.MediaTypeImageLayerGzip,
			data:       func(t *testing.T) []byte { return mockGzip(t, mockPAXTar(t)) },
			compressor: "erofs-lz4",
			expect:     expectExported,
		},
		{
			name:       "convert layer to native erofs with zstd compressor",
			mediaType:  ocispec.MediaTypeImageLayerGzip,
			data:       func(t *testing.T) []byte { return mockGzip(t, mockPAXTar(t)) },
			compressor: "erofs-zstd",
			expect:     expectExported,
		},
		{
			name:      "reject truncated tar without hanging",
			mediaType: ocispec.MediaTypeImageLayer,
			data: func(t *testing.T) []byte {
				return mockTar(t, "file", make([]byte, 4096))[:600]
			},
			expect: expectRejected,
		},
		{
			name:      "reject truncated gzip without hanging",
			mediaType: ocispec.MediaTypeImageLayerGzip,
			data: func(t *testing.T) []byte {
				data := mockGzip(t, mockTar(t, "file", make([]byte, 4096)))
				return data[:len(data)-5]
			},
			expect: expectRejected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cs := mockStore(t)
			opt := nydus.PackOption{BuilderPath: builder, WorkDir: t.TempDir(), Compressor: tc.compressor}
			desc, err := convertLayer(ctx, cs, mockContent(t, cs, tc.mediaType, tc.data(t)), opt)

			tc.expect(t, ctx, cs, opt, desc, err)
		})
	}
}
