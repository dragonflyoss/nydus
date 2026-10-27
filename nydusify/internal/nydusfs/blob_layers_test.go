/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

type blobReadStore struct {
	content.Store
	openErr error
	readErr error
	reader  *blobReadCloser
}

func (s *blobReadStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	ra, err := s.Store.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	s.reader = &blobReadCloser{ReaderAt: ra, readErr: s.readErr}
	return s.reader, nil
}

type blobReadCloser struct {
	content.ReaderAt
	readErr error
	closed  bool
}

func (r *blobReadCloser) ReadAt(p []byte, off int64) (int, error) {
	if r.readErr != nil {
		n, err := r.ReaderAt.ReadAt(p[:len(p)/2], off)
		if err != nil {
			return n, err
		}
		return n, r.readErr
	}
	return r.ReaderAt.ReadAt(p, off)
}

func (r *blobReadCloser) Close() error {
	r.closed = true
	return r.ReaderAt.Close()
}

func TestHasNativeLayers(t *testing.T) {
	for _, kind := range []string{"chunked", "native", "short", "bad magic", "open failure", "read failure"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			base, err := local.NewStore(t.TempDir())
			require.NoError(t, err)
			data := make([]byte, nydus.NydusBlobFooterSize)
			copy(data, nydus.NydusBlobFooterMagic)
			switch kind {
			case "native":
				binary.LittleEndian.PutUint32(data[12:], 1<<1)
			case "short":
				data = data[:32]
			case "bad magic":
				data[0] ^= 1
			}
			desc := ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromBytes(data), Size: int64(len(data))}
			require.NoError(t, content.WriteBlob(ctx, base, "blob", bytes.NewReader(data), desc))
			store := &blobReadStore{Store: base}
			failure := errors.New("blob reader failed")
			switch kind {
			case "open failure":
				store.openErr = failure
			case "read failure":
				store.readErr = failure
			}
			img := &Image{Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
				{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("ignored bootstrap")},
				desc,
			}}}
			native, err := HasNativeLayers(ctx, store, img)
			switch kind {
			case "native", "chunked":
				require.NoError(t, err)
				require.Equal(t, kind == "native", native)
			case "open failure", "read failure":
				require.ErrorIs(t, err, failure)
				require.False(t, native)
			case "short":
				require.ErrorContains(t, err, "too small")
			case "bad magic":
				require.ErrorContains(t, err, "bad footer magic")
			}
			if store.reader != nil {
				require.True(t, store.reader.closed)
			}
		})
	}
}

func TestMaterializeBlobLayers(t *testing.T) {
	for _, kind := range []string{"success", "open failure", "read failure", "blocked output", "blocked directory"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			base, err := local.NewStore(t.TempDir())
			require.NoError(t, err)
			data := bytes.Repeat([]byte("blob data"), 4096)
			desc := ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: digest.FromBytes(data), Size: int64(len(data))}
			require.NoError(t, content.WriteBlob(ctx, base, "blob", bytes.NewReader(data), desc))
			img := &Image{Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
				{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("ignored bootstrap")},
				desc,
			}}}
			store := &blobReadStore{Store: base}
			failure := errors.New("blob reader failed")
			dir := t.TempDir()
			switch kind {
			case "open failure":
				store.openErr = failure
			case "read failure":
				store.readErr = failure
			case "blocked output":
				require.NoError(t, os.Mkdir(filepath.Join(dir, desc.Digest.Encoded()), 0o700))
			case "blocked directory":
				dir = filepath.Join(dir, "not-a-directory")
				require.NoError(t, os.WriteFile(dir, nil, 0o600))
			}
			err = MaterializeBlobLayers(ctx, store, img, dir)
			switch kind {
			case "success":
				require.NoError(t, err)
				got, err := os.ReadFile(filepath.Join(dir, desc.Digest.Encoded()))
				require.NoError(t, err)
				require.Equal(t, data, got)
				entries, err := os.ReadDir(dir)
				require.NoError(t, err)
				require.Len(t, entries, 1)
			case "open failure", "read failure":
				require.ErrorIs(t, err, failure)
			case "blocked output":
				require.ErrorContains(t, err, "create blob")
			case "blocked directory":
				require.ErrorContains(t, err, "create blob dir")
			}
			if store.reader != nil {
				require.True(t, store.reader.closed, "all opened readers must close on success and failure")
				_, err := store.reader.ReaderAt.ReadAt(make([]byte, 1), 0)
				require.Error(t, err)
				require.NotErrorIs(t, err, io.EOF)
			}
		})
	}
}
