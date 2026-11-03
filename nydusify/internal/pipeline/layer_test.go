package pipeline

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestStreamingLayerWithRealBuilder(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run real builder conversion/merge/export tests")
	}
	mtime := time.Unix(1700000001, 123456789)
	files := map[string][]byte{"small": []byte("hello"), "large": bytes.Repeat([]byte("payload"), 45000), ".wh.removed": nil}
	var source bytes.Buffer
	tarWriter := tar.NewWriter(&source)
	for _, name := range []string{"small", "large", ".wh.removed"} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Uid: 1234, Gid: 5678, Size: int64(len(files[name])), ModTime: mtime, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.WriteHeader(&tar.Header{Name: "device", Typeflag: tar.TypeChar, Mode: 0o600, Devmajor: 1, Devminor: 3}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for _, compressor := range []string{"none", "zstd", "lz4", "erofs-none", "erofs-lz4", "erofs-zstd"} {
		t.Run(compressor, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			work := t.TempDir()
			store, err := local.NewStore(filepath.Join(work, "content"))
			if err != nil {
				t.Fatal(err)
			}
			var packed bytes.Buffer
			gzipWriter := gzip.NewWriter(&packed)
			if _, err := gzipWriter.Write(source.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := gzipWriter.Close(); err != nil {
				t.Fatal(err)
			}
			digest, size, err := oci.CommitBlob(ctx, store, "source", "", nil, func(writer io.Writer) error { _, err := writer.Write(packed.Bytes()); return err })
			if err != nil {
				t.Fatal(err)
			}
			converted, err := convertLayer(ctx, store, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest, Size: size}, nydus.PackOption{BuilderPath: builder, WorkDir: work, Compressor: compressor})
			if err != nil {
				t.Fatal(err)
			}
			blob, err := content.ReadBlob(ctx, store, *converted)
			if err != nil {
				t.Fatal(err)
			}
			meta, err := nydus.ExtractBlobMeta(bytes.NewReader(blob), int64(len(blob)))
			if err != nil {
				t.Fatal(err)
			}
			native := strings.HasPrefix(compressor, "erofs-")
			switch {
			case native && meta != nil:
				t.Fatal("native layer must carry no blob meta")
			case !native && (len(meta) < 24 || string(meta[:8]) != "NDBLMETA" || binary.LittleEndian.Uint32(meta[12:16]) != 0):
				t.Fatal("not blob metadata without incompat features")
			}
			stage := filepath.Join(work, "stage")
			if err := os.Mkdir(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			staged, err := nydus.StageNydusMetadata(bytes.NewReader(blob), int64(len(blob)), converted.Digest.Encoded(), stage)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := filepath.Join(work, "bootstrap")
			if err := nydus.RunNydusMerge(ctx, nydus.MergeBuildOption{BuilderPath: builder, SourcePaths: []string{staged}, BootstrapPath: bootstrap}); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.CommandContext(ctx, builder, "check", "--bootstrap", bootstrap).CombinedOutput(); err != nil {
				t.Fatalf("check: %v: %s", err, output)
			}
			bootstrapData, err := os.ReadFile(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			var bundle bytes.Buffer
			bundleWriter := tar.NewWriter(&bundle)
			metaName := converted.Digest.Encoded() + ".blob.meta"
			if err := nydus.WriteBootstrapTar(bundleWriter, bootstrapData, []nydus.BlobMetaFile{{Name: metaName, Data: meta}}, nil); err != nil {
				t.Fatal(err)
			}
			if err := bundleWriter.Close(); err != nil {
				t.Fatal(err)
			}
			bundleReader := tar.NewReader(&bundle)
			foundMeta := false
			for {
				header, err := bundleReader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if header.Name == "image/"+metaName {
					data, err := io.ReadAll(bundleReader)
					if err != nil || !bytes.Equal(data, meta) {
						t.Fatalf("blob metadata changed during packaging: %v", err)
					}
					foundMeta = true
				}
			}
			if !foundMeta {
				t.Fatal("blob metadata missing from bootstrap layer")
			}
			path := filepath.Join(work, converted.Digest.Encoded())
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatal(err)
			}
			var exported bytes.Buffer
			if err := nydus.RunNydusExport(ctx, nydus.ExportOption{BuilderPath: builder, BlobPath: path}, &exported); err != nil {
				t.Fatal(err)
			}
			reader := tar.NewReader(&exported)
			seen := make(map[string]bool)
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				name := filepath.Clean(header.Name)
				if want, ok := files[name]; ok {
					data, err := io.ReadAll(reader)
					if err != nil || !bytes.Equal(data, want) {
						t.Fatalf("content %s: %v", name, err)
					}
					if header.Uid != 1234 || header.Gid != 5678 || !header.ModTime.Equal(mtime) {
						t.Fatalf("metadata %s: %+v", name, header)
					}
					seen[name] = true
				}
				if name == "device" {
					if header.Typeflag != tar.TypeChar || header.Devmajor != 1 || header.Devminor != 3 {
						t.Fatalf("device: %+v", header)
					}
					seen[name] = true
				}
			}
			if len(seen) != len(files)+1 {
				t.Fatalf("missing exports: %v", seen)
			}
		})
	}
}

func TestStreamingLayerRejectsTruncatedInput(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run real builder failure tests")
	}
	var source bytes.Buffer
	writer := tar.NewWriter(&source)
	if err := writer.WriteHeader(&tar.Header{Name: "file", Mode: 0o644, Size: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, gzipInput := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		work := t.TempDir()
		store, err := local.NewStore(filepath.Join(work, "content"))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		data := source.Bytes()[:600]
		mediaType := ocispec.MediaTypeImageLayer
		if gzipInput {
			var compressed bytes.Buffer
			encoder := gzip.NewWriter(&compressed)
			if _, err := encoder.Write(source.Bytes()); err != nil {
				cancel()
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				cancel()
				t.Fatal(err)
			}
			data = compressed.Bytes()[:compressed.Len()-5]
			mediaType = ocispec.MediaTypeImageLayerGzip
		}
		digest, size, err := oci.CommitBlob(ctx, store, "source", "", nil, func(writer io.Writer) error {
			_, err := writer.Write(data)
			return err
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		converted, err := convertLayer(ctx, store, ocispec.Descriptor{MediaType: mediaType, Digest: digest, Size: size}, nydus.PackOption{BuilderPath: builder, WorkDir: work})
		if err == nil || converted != nil || ctx.Err() != nil {
			cancel()
			t.Fatalf("truncated input was accepted or hung (gzip=%v): %v", gzipInput, err)
		}
		cancel()
	}
}

func TestLayerConvertFunc(t *testing.T) {
	tests := []struct {
		name     string
		canceled bool
		desc     ocispec.Descriptor
		expect   func(t *testing.T, desc *ocispec.Descriptor, err error)
	}{
		{
			name:     "rejects canceled context",
			canceled: true,
			desc:     mockGzipLayer,
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Nil(desc)
			},
		},
		{
			name: "skips image config",
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: mockGzipLayer.Digest},
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "skips nydus blob",
			desc: ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: mockGzipLayer.Digest},
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "skips nydus bootstrap",
			desc: mockBootstrapLayer,
			expect: func(t *testing.T, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(desc)
			},
		},
		{
			name: "wraps layer conversion error",
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

			desc, err := LayerConvertFunc(nydus.PackOption{BuilderPath: "/nonexistent/nydus", WorkDir: t.TempDir()})(ctx, newMockStore(t), tc.desc)
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
			name: "uses positive override",
			env:  "3",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.Equal(3, concurrency)
			},
		},
		{
			name: "defaults without override",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.GreaterOrEqual(concurrency, 2)
				assert.LessOrEqual(concurrency, 4)
			},
		},
		{
			name: "ignores zero override",
			env:  "0",
			expect: func(t *testing.T, concurrency int) {
				assert := assert.New(t)
				assert.GreaterOrEqual(concurrency, 2)
				assert.LessOrEqual(concurrency, 4)
			},
		},
		{
			name: "ignores invalid override",
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
