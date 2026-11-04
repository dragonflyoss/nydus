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

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockBlobData = []byte("blob bytes")

	mockBlobDigest = digest.FromBytes(mockBlobData)

	mockPartialBlobData = []byte("partial data longer than the replacement")

	mockBlobLabels = func(d digest.Digest) map[string]string {
		return map[string]string{nydus.LayerAnnotationUncompressed: d.String()}
	}

	mockWriteBlob = func(w io.Writer) error {
		_, err := w.Write(mockBlobData)
		return err
	}

	mockOldDesc = ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageConfig,
		Digest:      digest.FromString("old config"),
		Size:        10,
		Annotations: map[string]string{"kept": "annotation"},
	}

	mockBootstrapData = bytes.Repeat([]byte("bootstrap"), 1024)

	mockBlobMetas = []nydus.BlobMetaFile{{Name: "test.blob.meta", Data: []byte("meta")}}

	mockAppendFiles = []nydus.AppendFile{{Name: "extra.json", Data: []byte("{}")}}
)

func mockFile(t *testing.T, data []byte) string {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockIngest(t *testing.T, cs content.Store, ref string, data []byte) {
	w, err := cs.Writer(context.Background(), content.WithRef(ref))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func mockGzip(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func mockTar(t *testing.T, names ...string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(name)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}

		if _, err := tw.Write([]byte(name)); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

type mockContentStore struct {
	content.Store
	phase           string
	err             error
	cancel          context.CancelFunc
	aborted         bool
	abortContextErr error
	writerClosed    bool
	readerClosed    bool
}

func (s *mockContentStore) Abort(ctx context.Context, ref string) error {
	s.aborted = true
	s.abortContextErr = ctx.Err()
	return s.Store.Abort(ctx, ref)
}

func (s *mockContentStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	if s.phase == "open" {
		return nil, s.err
	}

	w, err := s.Store.Writer(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &mockWriter{Writer: w, store: s}, nil
}

func (s *mockContentStore) Info(ctx context.Context, d digest.Digest) (content.Info, error) {
	if s.phase == "info" {
		return content.Info{}, s.err
	}

	return s.Store.Info(ctx, d)
}

func (s *mockContentStore) Update(ctx context.Context, info content.Info, fieldpaths ...string) (content.Info, error) {
	if s.phase == "labels" {
		return content.Info{}, s.err
	}

	return s.Store.Update(ctx, info, fieldpaths...)
}

func (s *mockContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	ra, err := s.Store.ReaderAt(ctx, desc)
	if err != nil || s.phase != "read" {
		return ra, err
	}

	return &mockReaderAt{ReaderAt: ra, store: s}, nil
}

type mockWriter struct {
	content.Writer
	store *mockContentStore
}

func (w *mockWriter) Status() (content.Status, error) {
	if w.store.phase == "status" {
		return content.Status{}, w.store.err
	}

	return w.Writer.Status()
}

func (w *mockWriter) Truncate(size int64) error {
	if w.store.phase == "truncate" {
		return w.store.err
	}

	return w.Writer.Truncate(size)
}

func (w *mockWriter) Write(p []byte) (int, error) {
	if w.store.phase == "write" {
		if w.store.cancel != nil {
			w.store.cancel()
		}

		return 0, w.store.err
	}

	return w.Writer.Write(p)
}

func (w *mockWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	if w.store.phase == "commit" {
		return w.store.err
	}

	return w.Writer.Commit(ctx, size, expected, opts...)
}

func (w *mockWriter) Close() error {
	w.store.writerClosed = true
	return w.Writer.Close()
}

type mockReaderAt struct {
	content.ReaderAt
	store *mockContentStore
}

func (r *mockReaderAt) ReadAt([]byte, int64) (int, error) {
	return 0, r.store.err
}

func (r *mockReaderAt) Close() error {
	r.store.readerClosed = true
	return r.ReaderAt.Close()
}

func TestCommitBlob(t *testing.T) {
	mockInterruptedErr := errors.New("interrupted write")
	tests := []struct {
		name     string
		phase    string
		expected digest.Digest
		labels   func(digest.Digest) map[string]string
		write    func(io.Writer) error
		mock     func(t *testing.T, cs content.Store)
		expect   func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error)
	}{
		{
			name: "return write error and keep partial ingest",
			write: func(w io.Writer) error {
				if _, err := w.Write(mockPartialBlobData); err != nil {
					return err
				}

				return mockInterruptedErr
			},
			mock: func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockInterruptedErr)
				status, err := cs.Status(context.Background(), "blob")
				assert.NoError(err)
				assert.Positive(status.Offset)
			},
		},
		{
			name:     "truncate interrupted ingest",
			expected: mockBlobDigest,
			write:    mockWriteBlob,
			mock: func(t *testing.T, cs content.Store) {
				mockIngest(t, cs, "blob", mockPartialBlobData)
			},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBlobDigest, dgst)
				assert.Equal(int64(len(mockBlobData)), size)
				data, err := content.ReadBlob(context.Background(), cs, ocispec.Descriptor{Digest: dgst})
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
				_, err = cs.Status(context.Background(), "blob")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name:     "reject mismatched digest",
			expected: digest.FromString("wrong digest"),
			write:    mockWriteBlob,
			mock:     func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
				_, err = cs.Info(context.Background(), mockBlobDigest)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name:     "restore labels on existing blob",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock: func(t *testing.T, cs content.Store) {
				mockBlob(t, cs, "", mockBlobData)
			},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBlobDigest, dgst)
				assert.Equal(int64(len(mockBlobData)), size)
				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal(map[string]string{nydus.LayerAnnotationUncompressed: mockBlobDigest.String()}, info.Labels)
			},
		},
		{
			name:     "fail to open writer",
			phase:    "open",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock:     func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
			},
		},
		{
			name:     "fail to get writer status",
			phase:    "status",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock:     func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
				assert.True(cs.writerClosed)
			},
		},
		{
			name:     "fail to truncate writer",
			phase:    "truncate",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock: func(t *testing.T, cs content.Store) {
				mockIngest(t, cs, "blob", mockPartialBlobData)
			},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
				assert.True(cs.writerClosed)
			},
		},
		{
			name:     "fail to write blob",
			phase:    "write",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock:     func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
				assert.True(cs.writerClosed)
			},
		},
		{
			name:     "fail to commit blob",
			phase:    "commit",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock:     func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
				assert.True(cs.writerClosed)
			},
		},
		{
			name:     "fail to restore labels on existing blob",
			phase:    "labels",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock: func(t *testing.T, cs content.Store) {
				mockBlob(t, cs, "", mockBlobData)
			},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
				assert.True(cs.writerClosed)
			},
		},
		{
			name:     "fail to stat committed blob",
			phase:    "info",
			expected: mockBlobDigest,
			labels:   mockBlobLabels,
			write:    mockWriteBlob,
			mock:     func(t *testing.T, cs content.Store) {},
			expect: func(t *testing.T, cs *mockContentStore, dgst digest.Digest, size int64, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Empty(dgst)
				assert.Zero(size)
				assert.True(cs.writerClosed)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := &mockContentStore{Store: mockLabeledStore(t), phase: tc.phase, err: errors.New("content store " + tc.phase)}
			tc.mock(t, cs.Store)
			dgst, size, err := oci.CommitBlob(context.Background(), cs, "blob", tc.expected, tc.labels, tc.write)

			tc.expect(t, cs, dgst, size, err)
		})
	}
}

func TestWriteJSON(t *testing.T) {
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
				assert.NoError(err)
				data := []byte(`{"os":"linux"}`)
				want := ocispec.Descriptor{
					MediaType:   mockOldDesc.MediaType,
					Digest:      digest.FromBytes(data),
					Size:        int64(len(data)),
					Annotations: mockOldDesc.Annotations,
				}
				assert.Equal(&want, desc)
				stored, err := content.ReadBlob(context.Background(), cs, want)
				assert.NoError(err)
				assert.Equal(data, stored)
				info, err := cs.Info(context.Background(), want.Digest)
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
			cs := &mockContentStore{Store: mockLabeledStore(t), phase: tc.phase, err: errors.New("content store " + tc.phase)}
			desc, err := oci.WriteJSON(context.Background(), cs, tc.value, mockOldDesc, map[string]string{"gc": "label"})

			tc.expect(t, cs, desc, err)
		})
	}
}

func TestIngestBlobFile(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		dgst   digest.Digest
		expect func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error)
	}{
		{
			name: "digest computed from file",
			path: mockFile(t, mockBlobData),
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
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
			path: mockFile(t, mockBlobData),
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
			path: mockFile(t, mockBlobData),
			dgst: digest.FromString("other blob"),
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "commit blob to content store")
				assert.Empty(desc)
				_, err = cs.Info(context.Background(), mockBlobDigest)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "missing file",
			path: filepath.Join(t.TempDir(), "missing"),
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open blob file")
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "directory cannot be hashed",
			path: t.TempDir(),
			expect: func(t *testing.T, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "hash blob file")
				assert.Empty(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockLabeledStore(t)
			desc, err := oci.IngestBlobFile(context.Background(), cs, tc.path, tc.dgst)

			tc.expect(t, cs, desc, err)
		})
	}
}

func TestWriteBootstrapLayerFromFile(t *testing.T) {
	tests := []struct {
		name   string
		phase  string
		path   string
		expect func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "match layer written from bytes",
			path: mockFile(t, mockBootstrapData),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				want, err := oci.WriteBootstrapLayer(ctx, cs, mockBootstrapData, mockBlobMetas, mockAppendFiles)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(want, desc)
				contents := map[string][]byte{}
				assert.NoError(oci.WalkBootstrapLayer(ctx, cs, *want, func(header *tar.Header, reader *tar.Reader) error {
					if header.Typeflag != tar.TypeReg {
						return nil
					}

					data, err := io.ReadAll(reader)
					contents[header.Name] = data
					return err
				}))
				assert.Equal(map[string][]byte{
					"image/image.boot":     mockBootstrapData,
					"image/test.blob.meta": []byte("meta"),
					"image/extra.json":     []byte("{}"),
				}, contents)
			},
		},
		{
			name: "missing file",
			path: filepath.Join(t.TempDir(), "missing"),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "abort ingest when bootstrap cannot be read",
			path: t.TempDir(),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.Error(err)
				statuses, err := cs.ListStatuses(context.Background())
				assert.NoError(err)
				assert.Empty(statuses)
			},
		},
		{
			name:  "abort ingest when writer cannot be opened",
			phase: "open",
			path:  mockFile(t, mockBootstrapData),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Nil(desc)
				assert.True(cs.aborted)
				assert.NoError(cs.abortContextErr)
				statuses, err := cs.ListStatuses(context.Background())
				assert.NoError(err)
				assert.Empty(statuses)
			},
		},
		{
			name:  "abort ingest when writer status fails",
			phase: "status",
			path:  mockFile(t, mockBootstrapData),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Nil(desc)
				assert.True(cs.aborted)
				assert.NoError(cs.abortContextErr)
				assert.True(cs.writerClosed)
				statuses, err := cs.ListStatuses(context.Background())
				assert.NoError(err)
				assert.Empty(statuses)
			},
		},
		{
			name:  "abort ingest with canceled context when write fails",
			phase: "write",
			path:  mockFile(t, mockBootstrapData),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Nil(desc)
				assert.True(cs.aborted)
				assert.NoError(cs.abortContextErr)
				assert.ErrorIs(ctx.Err(), context.Canceled)
				assert.True(cs.writerClosed)
				statuses, err := cs.ListStatuses(context.Background())
				assert.NoError(err)
				assert.Empty(statuses)
			},
		},
		{
			name:  "abort ingest when commit fails",
			phase: "commit",
			path:  mockFile(t, mockBootstrapData),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Nil(desc)
				assert.True(cs.aborted)
				assert.NoError(cs.abortContextErr)
				assert.True(cs.writerClosed)
				statuses, err := cs.ListStatuses(context.Background())
				assert.NoError(err)
				assert.Empty(statuses)
			},
		},
		{
			name:  "abort ingest when committed layer cannot be stat",
			phase: "info",
			path:  mockFile(t, mockBootstrapData),
			expect: func(t *testing.T, ctx context.Context, cs *mockContentStore, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, cs.err)
				assert.Nil(desc)
				assert.True(cs.aborted)
				assert.NoError(cs.abortContextErr)
				assert.True(cs.writerClosed)
				statuses, err := cs.ListStatuses(context.Background())
				assert.NoError(err)
				assert.Empty(statuses)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cs := &mockContentStore{Store: mockLabeledStore(t), phase: tc.phase, err: errors.New("bootstrap ingest " + tc.phase), cancel: cancel}
			desc, err := oci.WriteBootstrapLayerFromFile(ctx, cs, tc.path, mockBlobMetas, mockAppendFiles)

			tc.expect(t, ctx, cs, desc, err)
		})
	}
}

func TestOpenDecompressedBlob(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		phase  string
		expect func(t *testing.T, cs *mockContentStore, reader io.ReadCloser, err error)
	}{
		{
			name: "gzip blob is decompressed",
			data: mockGzip(t, []byte("layer data")),
			expect: func(t *testing.T, cs *mockContentStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("layer data", string(data))
				assert.NoError(reader.Close())
			},
		},
		{
			name: "uncompressed blob is passed through",
			data: []byte("plain layer"),
			expect: func(t *testing.T, cs *mockContentStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("plain layer", string(data))
				assert.NoError(reader.Close())
			},
		},
		{
			name: "missing blob",
			expect: func(t *testing.T, cs *mockContentStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open blob reader")
				assert.Nil(reader)
			},
		},
		{
			name:  "unreadable blob releases its reader",
			data:  []byte("plain layer"),
			phase: "read",
			expect: func(t *testing.T, cs *mockContentStore, reader io.ReadCloser, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decompress blob")
				assert.ErrorIs(err, cs.err)
				assert.Nil(reader)
				assert.True(cs.readerClosed)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := &mockContentStore{Store: mockLabeledStore(t), phase: tc.phase, err: errors.New("blob read failed")}
			desc := ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			if tc.data != nil {
				desc = mockBlob(t, cs.Store, "", tc.data)
			}

			reader, err := oci.OpenDecompressedBlob(context.Background(), cs, desc)

			tc.expect(t, cs, reader, err)
		})
	}
}

func TestWalkBootstrapLayer(t *testing.T) {
	mockVisitErr := errors.New("visit failed")
	tests := []struct {
		name   string
		data   []byte
		visit  func(names *[]string) func(*tar.Header, *tar.Reader) error
		expect func(t *testing.T, names []string, err error)
	}{
		{
			name: "visits every entry in order",
			data: mockTar(t, "image/image.boot", "image/blob.blob.meta"),
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
			data: mockTar(t, "image/image.boot", "image/blob.blob.meta"),
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
			cs := mockLabeledStore(t)
			desc := ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			if tc.data != nil {
				desc = mockBlob(t, cs, "", tc.data)
			}

			var names []string
			err := oci.WalkBootstrapLayer(context.Background(), cs, desc, tc.visit(&names))

			tc.expect(t, names, err)
		})
	}
}
