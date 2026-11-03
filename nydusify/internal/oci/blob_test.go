/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package oci_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"github.com/stretchr/testify/assert"
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
	reader          *failingReaderAt
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

func (s *failingStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	ra, err := s.Store.ReaderAt(ctx, desc)
	if err != nil || s.phase != "read" {
		return ra, err
	}
	s.reader = &failingReaderAt{ReaderAt: ra, err: s.err}
	return s.reader, nil
}

type failingReaderAt struct {
	content.ReaderAt
	err    error
	closed bool
}

func (r *failingReaderAt) ReadAt([]byte, int64) (int, error) {
	return 0, r.err
}

func (r *failingReaderAt) Close() error {
	r.closed = true
	return r.ReaderAt.Close()
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

func TestWriteJSON(t *testing.T) {
	mockOldDesc := ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageConfig,
		Digest:      digest.FromString("old config"),
		Size:        10,
		Annotations: map[string]string{"kept": "annotation"},
	}
	tests := []struct {
		name   string
		value  any
		phase  string
		expect func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error)
	}{
		{
			name:  "commits json with labels",
			value: map[string]string{"os": "linux"},
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				data := []byte(`{"os":"linux"}`)
				assert.Equal(&ocispec.Descriptor{
					MediaType:   mockOldDesc.MediaType,
					Digest:      digest.FromBytes(data),
					Size:        int64(len(data)),
					Annotations: mockOldDesc.Annotations,
				}, desc)
				stored, err := content.ReadBlob(context.Background(), cs, *desc)
				assert.NoError(err)
				assert.Equal(data, stored)
				info, err := cs.Info(context.Background(), desc.Digest)
				assert.NoError(err)
				assert.Equal(map[string]string{"gc": "label"}, info.Labels)
			},
		},
		{
			name:  "value cannot be marshaled",
			value: make(chan int),
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "marshal json")
				assert.Nil(desc)
			},
		},
		{
			name:  "content store rejects write",
			value: map[string]string{"os": "linux"},
			phase: "open",
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "commit json")
				assert.ErrorContains(err, "content store open")
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			cs := &failingStore{Store: provider.ContentStore(), phase: tc.phase, err: errors.New("content store " + tc.phase)}
			desc, err := oci.WriteJSON(context.Background(), cs, tc.value, mockOldDesc, map[string]string{"gc": "label"})
			tc.expect(t, cs, desc, err)
		})
	}
}

func TestIngestBlobFile(t *testing.T) {
	mockBlobData := []byte("nydus full blob")
	mockBlobDigest := digest.FromBytes(mockBlobData)
	tests := []struct {
		name   string
		path   func(t *testing.T) string
		dgst   digest.Digest
		expect func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error)
	}{
		{
			name: "digest computed from file",
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "blob")
				assert.NoError(t, os.WriteFile(path, mockBlobData, 0o600))
				return path
			},
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				assert.Equal(ocispec.Descriptor{
					MediaType: nydus.MediaTypeNydusBlob,
					Digest:    mockBlobDigest,
					Size:      int64(len(mockBlobData)),
					Annotations: map[string]string{
						nydus.LayerAnnotationUncompressed: mockBlobDigest.String(),
						nydus.LayerAnnotationNydusBlob:    "true",
					},
				}, desc)
				stored, err := content.ReadBlob(context.Background(), cs, desc)
				assert.NoError(err)
				assert.Equal(mockBlobData, stored)
				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal(mockBlobDigest.String(), info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "provided digest is trusted",
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "blob")
				assert.NoError(t, os.WriteFile(path, mockBlobData, 0o600))
				return path
			},
			dgst: mockBlobDigest,
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBlobDigest, desc.Digest)
				assert.Equal(int64(len(mockBlobData)), desc.Size)
			},
		},
		{
			name: "mismatched digest is rejected",
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "blob")
				assert.NoError(t, os.WriteFile(path, mockBlobData, 0o600))
				return path
			},
			dgst: digest.FromString("other blob"),
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "commit blob to content store")
				assert.Empty(desc)
				_, err = cs.Info(context.Background(), mockBlobDigest)
				assert.True(errdefs.IsNotFound(err))
			},
		},
		{
			name: "missing file",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing")
			},
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open blob file")
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "directory cannot be hashed",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "hash blob file")
				assert.Empty(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			desc, err := oci.IngestBlobFile(context.Background(), provider.ContentStore(), tc.path(t), tc.dgst)
			tc.expect(t, provider.ContentStore(), desc, err)
		})
	}
}

func TestOpenDecompressedBlob(t *testing.T) {
	var mockGzipLayer bytes.Buffer
	gw := gzip.NewWriter(&mockGzipLayer)
	_, err := gw.Write([]byte("layer data"))
	assert.NoError(t, err)
	assert.NoError(t, gw.Close())
	tests := []struct {
		name   string
		data   []byte
		phase  string
		expect func(t *testing.T, cs *failingStore, reader io.ReadCloser, err error)
	}{
		{
			name: "gzip blob is decompressed",
			data: mockGzipLayer.Bytes(),
			expect: func(t *testing.T, cs *failingStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("layer data", string(data))
				assert.NoError(reader.Close())
			},
		},
		{
			name: "uncompressed blob is passed through",
			data: []byte("plain layer"),
			expect: func(t *testing.T, cs *failingStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("plain layer", string(data))
				assert.NoError(reader.Close())
			},
		},
		{
			name: "missing blob",
			expect: func(t *testing.T, cs *failingStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open blob reader")
				assert.Nil(reader)
			},
		},
		{
			name:  "unreadable blob releases its reader",
			data:  []byte("plain layer"),
			phase: "read",
			expect: func(t *testing.T, cs *failingStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decompress blob")
				assert.ErrorIs(err, cs.err)
				assert.Nil(reader)
				assert.True(cs.reader.closed)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			desc := ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			if tc.data != nil {
				desc = ocispec.Descriptor{Digest: digest.FromBytes(tc.data), Size: int64(len(tc.data))}
				if !assert.NoError(t, content.WriteBlob(context.Background(), provider.ContentStore(), "layer", bytes.NewReader(tc.data), desc)) {
					t.FailNow()
				}
			}
			cs := &failingStore{Store: provider.ContentStore(), phase: tc.phase, err: errors.New("blob read failed")}
			reader, err := oci.OpenDecompressedBlob(context.Background(), cs, desc)
			tc.expect(t, cs, reader, err)
		})
	}
}

func TestWalkBootstrapLayer(t *testing.T) {
	var mockBootstrapTar bytes.Buffer
	tw := tar.NewWriter(&mockBootstrapTar)
	for _, name := range []string{"image/image.boot", "image/blob.blob.meta"} {
		assert.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(name)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(name))
		assert.NoError(t, err)
	}
	assert.NoError(t, tw.Close())
	mockVisitErr := errors.New("visit failed")
	tests := []struct {
		name   string
		data   []byte
		visit  func(names *[]string) func(*tar.Header, *tar.Reader) error
		expect func(t *testing.T, names []string, err error)
	}{
		{
			name: "visits every entry in order",
			data: mockBootstrapTar.Bytes(),
			visit: func(names *[]string) func(*tar.Header, *tar.Reader) error {
				return func(header *tar.Header, reader *tar.Reader) error {
					data, err := io.ReadAll(reader)
					*names = append(*names, header.Name+"="+string(data))
					return err
				}
			},
			expect: func(t *testing.T, names []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"image/image.boot=image/image.boot", "image/blob.blob.meta=image/blob.blob.meta"}, names)
			},
		},
		{
			name: "visitor error stops the walk",
			data: mockBootstrapTar.Bytes(),
			visit: func(names *[]string) func(*tar.Header, *tar.Reader) error {
				return func(header *tar.Header, _ *tar.Reader) error {
					*names = append(*names, header.Name)
					return mockVisitErr
				}
			},
			expect: func(t *testing.T, names []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockVisitErr)
				assert.Equal([]string{"image/image.boot"}, names)
			},
		},
		{
			name: "corrupt tar",
			data: []byte("not a tar archive"),
			visit: func(names *[]string) func(*tar.Header, *tar.Reader) error {
				return func(header *tar.Header, _ *tar.Reader) error {
					*names = append(*names, header.Name)
					return nil
				}
			},
			expect: func(t *testing.T, names []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read bootstrap tar")
				assert.Empty(names)
			},
		},
		{
			name: "missing layer",
			visit: func(names *[]string) func(*tar.Header, *tar.Reader) error {
				return func(header *tar.Header, _ *tar.Reader) error {
					*names = append(*names, header.Name)
					return nil
				}
			},
			expect: func(t *testing.T, names []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open bootstrap layer")
				assert.Empty(names)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			desc := ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			if tc.data != nil {
				desc = ocispec.Descriptor{Digest: digest.FromBytes(tc.data), Size: int64(len(tc.data))}
				if !assert.NoError(t, content.WriteBlob(context.Background(), provider.ContentStore(), "bootstrap", bytes.NewReader(tc.data), desc)) {
					t.FailNow()
				}
			}
			var names []string
			err = oci.WalkBootstrapLayer(context.Background(), provider.ContentStore(), desc, tc.visit(&names))
			tc.expect(t, names, err)
		})
	}
}
