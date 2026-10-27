/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestExtractBootstrapLayer(t *testing.T) {
	const metaName = "blob.blob.meta"
	for _, tc := range []struct {
		name     string
		omitBoot bool
		truncate string
		block    string
		want     string
	}{
		{name: "valid"},
		{name: "missing bootstrap", omitBoot: true, want: "not found in layer"},
		{name: "truncated bootstrap", truncate: nydus.BootstrapFileNameInLayer, want: "write bootstrap file"},
		{name: "truncated metadata", truncate: "image/" + metaName, want: "write blob meta"},
		{name: "bootstrap output blocked", block: "image.boot", want: "write bootstrap file"},
		{name: "metadata output blocked", block: metaName, want: "write blob meta"},
	} {
		for _, encoding := range []string{"tar", "gzip"} {
			t.Run(tc.name+"/"+encoding, func(t *testing.T) {
				var archive bytes.Buffer
				tw := tar.NewWriter(&archive)
				cut := 0
				for _, entry := range []struct{ name, data string }{
					{nydus.BootstrapFileNameInLayer, "bootstrap bytes"},
					{"image/" + metaName, "metadata bytes"},
					{"image/ignored", "not an extracted artifact"},
				} {
					if tc.omitBoot && entry.name == nydus.BootstrapFileNameInLayer {
						continue
					}

					require.NoError(t, tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.data))}))
					_, err := io.WriteString(tw, entry.data)
					require.NoError(t, err)
					if entry.name == tc.truncate {
						cut = archive.Len() - 1
					}
				}
				require.NoError(t, tw.Close())
				data := archive.Bytes()
				if tc.truncate != "" {
					require.Positive(t, cut)
					data = data[:cut]
				}
				if encoding == "gzip" {
					var compressed bytes.Buffer
					gw := gzip.NewWriter(&compressed)
					_, err := gw.Write(data)
					require.NoError(t, err)
					require.NoError(t, gw.Close())
					data = compressed.Bytes()
				}
				ctx := context.Background()
				store, err := local.NewStore(t.TempDir())
				require.NoError(t, err)
				desc := ocispec.Descriptor{Digest: digest.FromBytes(data), Size: int64(len(data))}
				require.NoError(t, content.WriteBlob(ctx, store, "bootstrap", bytes.NewReader(data), desc))
				dest := t.TempDir()
				if tc.block != "" {
					require.NoError(t, os.Mkdir(filepath.Join(dest, tc.block), 0o700))
				}

				boot, metas, err := ExtractBootstrapLayer(ctx, store, desc, dest)
				if tc.want != "" {
					require.ErrorContains(t, err, tc.want)
					require.Empty(t, boot)
					require.Empty(t, metas)
					if tc.truncate != "" {
						require.ErrorIs(t, err, io.ErrUnexpectedEOF)
					}
					return
				}
				require.NoError(t, err)
				require.Equal(t, filepath.Join(dest, "image.boot"), boot)
				require.Equal(t, []string{filepath.Join(dest, metaName)}, metas)
				bootData, err := os.ReadFile(boot)
				require.NoError(t, err)
				require.Equal(t, "bootstrap bytes", string(bootData))
				metaData, err := os.ReadFile(metas[0])
				require.NoError(t, err)
				require.Equal(t, "metadata bytes", string(metaData))
				entries, err := os.ReadDir(dest)
				require.NoError(t, err)
				require.Len(t, entries, 2)
			})
		}
	}
}

func TestLinkBlobMetaFiles(t *testing.T) {
	t.Run("concurrent same destination", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "blob.blob.meta")
		data := bytes.Repeat([]byte("blob metadata"), 4096)
		require.NoError(t, os.WriteFile(src, data, 0o600))
		cache := t.TempDir()
		require.NoError(t, LinkBlobMetaFiles(context.Background(), slices.Repeat([]string{src}, 32), cache))
		require.NoError(t, LinkBlobMetaFiles(context.Background(), []string{src}, cache))
		got, err := os.ReadFile(filepath.Join(cache, filepath.Base(src)))
		require.NoError(t, err)
		require.Equal(t, data, got)
		entries, err := os.ReadDir(cache)
		require.NoError(t, err)
		require.Len(t, entries, 1)
	})
	for _, source := range []string{"missing", "directory"} {
		t.Run(source, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "blob.blob.meta")
			if source == "directory" {
				require.NoError(t, os.Mkdir(src, 0o700))
			}
			cache := t.TempDir()
			err := LinkBlobMetaFiles(context.Background(), []string{src}, cache)
			if source == "missing" {
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.ErrorContains(t, err, "copy data")
			}
			entries, err := os.ReadDir(cache)
			require.NoError(t, err)
			require.Empty(t, entries, "failed copy must not publish a file or leave a temporary file")
		})
	}
}
