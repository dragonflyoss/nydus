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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type metadataOnlyReader struct {
	*bytes.Reader
	dataEnd int64
}

func (r metadataOnlyReader) ReadAt(p []byte, off int64) (int, error) {
	if off < r.dataEnd {
		return 0, errors.New("merge must not read the blob data region")
	}
	return r.Reader.ReadAt(p, off)
}

type limitedDestination struct {
	remaining int
	err       error
}

func (w *limitedDestination) Write(p []byte) (int, error) {
	n := min(w.remaining, len(p))
	w.remaining -= n
	if n < len(p) {
		return n, w.err
	}
	return n, nil
}

func TestBuildBlobAndMerge(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run SDK build/merge integrations")
	}
	for _, compressor := range []string{"zstd", "erofs-lz4"} {
		t.Run(compressor, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			scratch := t.TempDir()
			var layers []Layer
			var wantDigests []digest.Digest
			wantFiles := map[string][]byte{"image/extra": []byte("appended metadata")}
			for _, name := range []string{"lower", "upper"} {
				source := t.TempDir()
				payload := []byte(name + " payload")
				require.NoError(t, os.WriteFile(filepath.Join(source, name), payload, 0o644))
				var blob bytes.Buffer
				require.NoError(t, BuildBlob(ctx, &blob, source, PackOption{
					BuilderPath: builder, WorkDir: scratch, Compressor: compressor,
				}))
				dgst := digest.FromBytes(blob.Bytes())
				blobPath := filepath.Join(t.TempDir(), dgst.Encoded())
				require.NoError(t, os.WriteFile(blobPath, blob.Bytes(), 0o600))
				var exported bytes.Buffer
				require.NoError(t, RunNydusExport(ctx, ExportOption{BuilderPath: builder, BlobPath: blobPath}, &exported))
				files := readSDKArchive(t, exported.Bytes())
				require.Equal(t, payload, files[name], "BuildBlob must preserve the source file")

				footer := blob.Bytes()[blob.Len()-NydusBlobFooterSize:]
				dataEnd := int64(binary.LittleEndian.Uint64(footer[40:48]))
				require.Positive(t, dataEnd, "fixture must contain a data region")
				layers = append(layers, Layer{Digest: dgst, ReaderAt: metadataOnlyReader{bytes.NewReader(blob.Bytes()), dataEnd}})
				wantDigests = append(wantDigests, dgst)
				if compressor == "zstd" {
					offset := binary.LittleEndian.Uint64(footer[64:72])
					size := binary.LittleEndian.Uint64(footer[72:80])
					require.Positive(t, size)
					wantFiles["image/"+dgst.Encoded()+".blob.meta"] = blob.Bytes()[offset : offset+size]
				}
			}
			opt := MergeOption{BuilderPath: builder, WorkDir: scratch,
				AppendFiles: []AppendFile{{Name: "extra", Data: wantFiles["image/extra"]}}}
			var output bytes.Buffer
			gotDigests, err := Merge(ctx, layers, &output, opt)
			require.NoError(t, err)
			require.Equal(t, wantDigests, gotDigests, "SDK preserves layer order")
			files := readSDKArchive(t, output.Bytes())
			bootstrap := files[BootstrapFileNameInLayer]
			require.NotEmpty(t, bootstrap)
			delete(files, BootstrapFileNameInLayer)
			require.Equal(t, wantFiles, files, "native layers must not gain blob-meta sidecars")
			bootstrapPath := filepath.Join(t.TempDir(), "bootstrap")
			require.NoError(t, os.WriteFile(bootstrapPath, bootstrap, 0o600))
			check, err := exec.CommandContext(ctx, builder, "check", "--bootstrap", bootstrapPath).CombinedOutput()
			require.NoError(t, err, "%s", check)

			for _, remaining := range []int{0, output.Len() - 1} {
				expected := errors.New("destination failed")
				_, err := Merge(ctx, layers, &limitedDestination{remaining, expected}, opt)
				require.ErrorIs(t, err, expected, "both tar writes and final close must propagate failures")
			}
			opt.BuilderPath = filepath.Join(t.TempDir(), "missing-builder")
			output.Reset()
			gotDigests, err = Merge(ctx, layers, &output, opt)
			require.ErrorContains(t, err, "nydus merge")
			require.Nil(t, gotDigests)
			require.Zero(t, output.Len(), "builder failure must not publish a tar")
			entries, err := os.ReadDir(scratch)
			require.NoError(t, err)
			require.Empty(t, entries, "successful and failed merges must clean staged files")
		})
	}
}

func readSDKArchive(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if header.Typeflag == tar.TypeDir {
			continue
		}
		_, exists := files[header.Name]
		require.False(t, exists, "duplicate tar entry %s", header.Name)
		files[header.Name], err = io.ReadAll(reader)
		require.NoError(t, err)
	}
	return files
}

func TestMergeRejectsInvalidInputs(t *testing.T) {
	for _, layers := range [][]Layer{nil, {{Digest: digest.FromString("bad"), ReaderAt: bytes.NewReader([]byte("not a blob"))}}} {
		var output bytes.Buffer
		scratch := t.TempDir()
		digests, err := Merge(context.Background(), layers, &output, MergeOption{WorkDir: scratch})
		require.Error(t, err)
		require.Nil(t, digests)
		require.Zero(t, output.Len(), "invalid input must not publish an archive")
		entries, err := os.ReadDir(scratch)
		require.NoError(t, err)
		require.Empty(t, entries)
	}
}
