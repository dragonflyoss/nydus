/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package oci_test

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestBootstrapFileAndBytesHaveIdenticalLayers(t *testing.T) {
	ctx := context.Background()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	data := bytes.Repeat([]byte("bootstrap"), 1024)
	path := filepath.Join(t.TempDir(), "image.boot")
	require.NoError(t, os.WriteFile(path, data, 0644))
	meta := []nydus.BlobMetaFile{{Name: "test.blob.meta", Data: []byte("meta")}}
	extra := []nydus.AppendFile{{Name: "extra.json", Data: []byte("{}")}}
	original, err := oci.WriteBootstrapLayer(ctx, provider.ContentStore(), data, meta, extra)
	require.NoError(t, err)
	streamed, err := oci.WriteBootstrapLayerFromFile(ctx, provider.ContentStore(), path, meta, extra)
	require.NoError(t, err)
	require.Equal(t, original, streamed)
	contents := map[string][]byte{}
	require.NoError(t, oci.WalkBootstrapLayer(ctx, provider.ContentStore(), *streamed, func(header *tar.Header, reader *tar.Reader) error {
		if header.Typeflag == tar.TypeReg {
			var err error
			contents[header.Name], err = io.ReadAll(reader)
			return err
		}
		return nil
	}))
	require.Equal(t, data, contents["image/image.boot"])
	require.Equal(t, []byte("meta"), contents["image/test.blob.meta"])
	require.Equal(t, []byte("{}"), contents["image/extra.json"])
	_, err = oci.WriteBootstrapLayerFromFile(ctx, provider.ContentStore(), path+"-missing", nil, nil)
	require.Error(t, err)
	_, err = oci.WriteBootstrapLayerFromFile(ctx, provider.ContentStore(), filepath.Dir(path), nil, nil)
	require.Error(t, err)
	statuses, err := provider.ContentStore().ListStatuses(ctx)
	require.NoError(t, err)
	require.Empty(t, statuses, "bootstrap failure must abort its partial ingest")
}

func TestCommitBlobRetriesInterruptedIngest(t *testing.T) {
	ctx := context.Background()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	store := provider.ContentStore()
	interrupted := errors.New("interrupted write")
	_, _, err = oci.CommitBlob(ctx, store, "retry", "", nil, func(w io.Writer) error {
		_, err := io.WriteString(w, "partial data longer than the replacement")
		require.NoError(t, err)
		return interrupted
	})
	require.ErrorIs(t, err, interrupted)
	status, err := store.Status(ctx, "retry")
	require.NoError(t, err)
	require.Positive(t, status.Offset)

	data := []byte("replacement")
	expected := digest.FromBytes(data)
	got, size, err := oci.CommitBlob(ctx, store, "retry", expected, nil, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, expected, got)
	require.Equal(t, int64(len(data)), size)
	actual, err := content.ReadBlob(ctx, store, ocispec.Descriptor{Digest: got})
	require.NoError(t, err)
	require.Equal(t, data, actual)
	_, err = store.Status(ctx, "retry")
	require.True(t, errdefs.IsNotFound(err), "committed ingest must be removed: %v", err)
}

func TestCommitBlobValidatesDigestAndRestoresLabels(t *testing.T) {
	ctx := context.Background()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	store := provider.ContentStore()
	data := []byte("immutable blob")
	expected := digest.FromBytes(data)
	write := func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}
	_, _, err = oci.CommitBlob(ctx, store, "wrong", digest.FromString("wrong digest"), nil, write)
	require.Error(t, err)
	_, err = store.Info(ctx, expected)
	require.True(t, errdefs.IsNotFound(err), "digest mismatch must not publish content: %v", err)

	_, _, err = oci.CommitBlob(ctx, store, "correct", expected, nil, write)
	require.NoError(t, err)
	labels := map[string]string{"containerd.io/uncompressed": expected.String()}
	for range 2 {
		got, size, err := oci.CommitBlob(ctx, store, "reuse", expected,
			func(d digest.Digest) map[string]string {
				require.Equal(t, expected, d)
				return labels
			}, write)
		require.NoError(t, err)
		require.Equal(t, expected, got)
		require.Equal(t, int64(len(data)), size)
		info, err := store.Info(ctx, got)
		require.NoError(t, err)
		require.Equal(t, labels, info.Labels)
	}
}

type failingStore struct {
	content.Store
	phase           string
	err             error
	writer          *failingWriter
	abortContextErr error
	aborted         bool
	cancel          context.CancelFunc
}

func (s *failingStore) Abort(ctx context.Context, ref string) error {
	s.aborted = true
	s.abortContextErr = ctx.Err()
	return s.Store.Abort(ctx, ref)
}

func (s *failingStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	if s.phase == "open" {
		return nil, s.err
	}
	w, err := s.Store.Writer(ctx, opts...)
	if err != nil {
		return nil, err
	}
	s.writer = &failingWriter{Writer: w, store: s}
	return s.writer, nil
}

func (s *failingStore) Info(ctx context.Context, d digest.Digest) (content.Info, error) {
	if s.phase == "info" {
		return content.Info{}, s.err
	}
	return s.Store.Info(ctx, d)
}

func (s *failingStore) Update(ctx context.Context, info content.Info, fields ...string) (content.Info, error) {
	return content.Info{}, s.err
}

type failingWriter struct {
	content.Writer
	store  *failingStore
	closed bool
}

func (w *failingWriter) Status() (content.Status, error) {
	if w.store.phase == "status" {
		return content.Status{}, w.store.err
	}
	return w.Writer.Status()
}

func (w *failingWriter) Truncate(size int64) error {
	return w.store.err
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.store.phase == "write" {
		if w.store.cancel != nil {
			w.store.cancel()
		}
		return 0, w.store.err
	}
	return w.Writer.Write(p)
}

func (w *failingWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	if w.store.phase == "commit" {
		return w.store.err
	}
	return w.Writer.Commit(ctx, size, expected, opts...)
}

func (w *failingWriter) Close() error {
	w.closed = true
	return w.Writer.Close()
}

func TestCommitBlobPropagatesStoreErrors(t *testing.T) {
	for _, phase := range []string{"open", "status", "truncate", "write", "commit", "labels", "info"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			require.NoError(t, err)
			base := provider.ContentStore()
			data := []byte("blob bytes")
			if phase == "truncate" {
				w, err := base.Writer(ctx, content.WithRef("blob"))
				require.NoError(t, err)
				_, err = w.Write([]byte("partial"))
				require.NoError(t, err)
				require.NoError(t, w.Close())
			}
			if phase == "labels" {
				desc := ocispec.Descriptor{Digest: digest.FromBytes(data), Size: int64(len(data))}
				require.NoError(t, content.WriteBlob(ctx, base, "existing", bytes.NewReader(data), desc))
			}
			failure := errors.New("content store " + phase)
			store := &failingStore{Store: base, phase: phase, err: failure}
			got, size, err := oci.CommitBlob(ctx, store, "blob", digest.FromBytes(data),
				func(digest.Digest) map[string]string { return map[string]string{"test": "label"} },
				func(w io.Writer) error {
					_, err := w.Write(data)
					return err
				})
			require.ErrorIs(t, err, failure)
			require.Empty(t, got)
			require.Zero(t, size)
			if store.writer != nil {
				require.True(t, store.writer.closed, "failed ingest must release its writer")
			}
		})
	}
}

func TestBootstrapFileAbortsFailedIngest(t *testing.T) {
	for _, phase := range []string{"open", "status", "write", "commit", "info"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "image.boot")
			require.NoError(t, os.WriteFile(path, []byte("bootstrap data"), 0600))
			failure := errors.New("bootstrap ingest " + phase)
			store := &failingStore{Store: provider.ContentStore(), phase: phase, err: failure}
			if phase == "write" {
				store.cancel = cancel
			}
			desc, err := oci.WriteBootstrapLayerFromFile(ctx, store, path, nil, nil)
			require.ErrorIs(t, err, failure)
			require.Nil(t, desc)
			require.True(t, store.aborted)
			require.NoError(t, store.abortContextErr)
			if phase == "write" {
				require.ErrorIs(t, ctx.Err(), context.Canceled)
			}
			if store.writer != nil {
				require.True(t, store.writer.closed)
			}
			statuses, err := store.ListStatuses(context.Background())
			require.NoError(t, err)
			require.Empty(t, statuses, "failed packaging must not retain a partial ingest")
		})
	}
}
