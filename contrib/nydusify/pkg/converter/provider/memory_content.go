package provider

import (
	"bytes"
	"context"
	"io"
	"log"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type memoryContentStore struct {
	mu    sync.Mutex
	blobs map[digest.Digest]*bytes.Buffer
}

func NewMemoryContentStore() content.Store {
	return &memoryContentStore{
		blobs: make(map[digest.Digest]*bytes.Buffer),
	}
}

type memoryWriter struct {
	buf    *bytes.Buffer
	store  *memoryContentStore
	dgst   digest.Digest
	off    int64
	closed bool
}

func (m *memoryContentStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	log.Println("[memoryContentStore] Writer: create new memory writer")
	return &memoryWriter{
		buf:   &bytes.Buffer{},
		store: m,
	}, nil
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := w.buf.Write(p)
	w.off += int64(n)
	return n, err
}

func (w *memoryWriter) Close() error {
	w.closed = true
	return nil
}

func (w *memoryWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	log.Printf("[memoryContentStore] Commit: commit blob %s, size=%d", expected.String(), w.buf.Len())
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	w.dgst = expected
	w.store.blobs[expected] = w.buf
	return nil
}

func (w *memoryWriter) Truncate(size int64) error {
	return nil
}

func (w *memoryWriter) Status() (content.Status, error) {
	return content.Status{
		Offset: w.off,
	}, nil
}

func (w *memoryWriter) Digest() digest.Digest {
	return w.dgst
}

func (w *memoryWriter) Size() int64 {
	return int64(w.buf.Len())
}

type memoryReaderAt struct {
	*bytes.Reader
}

func (m *memoryReaderAt) Close() error {
	return nil
}

func (m *memoryReaderAt) Size() int64 {
	return int64(m.Reader.Len())
}

func (m *memoryContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	log.Printf("[memoryContentStore] ReaderAt: read blob %s", desc.Digest.String())
	m.mu.Lock()
	defer m.mu.Unlock()
	buf, ok := m.blobs[desc.Digest]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	return &memoryReaderAt{bytes.NewReader(buf.Bytes())}, nil
}

func (m *memoryContentStore) Reader(ctx context.Context, desc digest.Digest) (io.ReadCloser, error) {
	log.Printf("[memoryContentStore] Reader: read blob %s", desc.String())
	m.mu.Lock()
	defer m.mu.Unlock()
	buf, ok := m.blobs[desc]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func (m *memoryContentStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf, ok := m.blobs[dgst]
	if !ok {
		return content.Info{}, errdefs.ErrNotFound
	}
	return content.Info{
		Digest: dgst,
		Size:   int64(buf.Len()),
	}, nil
}

func (m *memoryContentStore) Abort(ctx context.Context, ref string) error {
	return nil
}

func (m *memoryContentStore) Status(ctx context.Context, ref string) (content.Status, error) {
	return content.Status{Ref: ref}, nil
}

func (m *memoryContentStore) ListStatuses(ctx context.Context, filters ...string) ([]content.Status, error) {
	return nil, nil
}

func (m *memoryContentStore) Delete(ctx context.Context, dgst digest.Digest) error {
	log.Printf("[memoryContentStore] Delete: delete blob %s", dgst.String())
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs, dgst)
	return nil
}

func (m *memoryContentStore) Update(ctx context.Context, info content.Info, fieldpaths ...string) (content.Info, error) {
	return info, nil
}

func (m *memoryContentStore) Walk(ctx context.Context, fn content.WalkFunc, filters ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for dgst, buf := range m.blobs {
		info := content.Info{
			Digest: dgst,
			Size:   int64(buf.Len()),
		}
		if err := fn(info); err != nil {
			return err
		}
	}
	return nil
}
