package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

// contextKey is a type for context keys to avoid conflicts
type contextKey string

const (
	streamContextKey contextKey = "useStream"
)

type memoryBlob struct {
	// data is the content of the blob
	data   []byte
	digest digest.Digest
	size   int64
}

type streamBlob struct {
	// pr is the reader of the stream blob
	pr *io.PipeReader
	// pw is the writer of the stream blob
	pw        *io.PipeWriter
	digest    digest.Digest // digest of the blob
	size      int64         // size of the blob
	done      chan struct{} // done signal
	dataCache *bytes.Buffer // cache of the read data, support random read
	mu        sync.RWMutex  // mutex of the data cache
}

type memoryContentStore struct {
	mu          sync.RWMutex
	blobs       map[digest.Digest]*memoryBlob
	streamBlobs map[digest.Digest]*streamBlob
}

func NewMemoryContentStore() content.Store {
	return &memoryContentStore{
		blobs:       make(map[digest.Digest]*memoryBlob),
		streamBlobs: make(map[digest.Digest]*streamBlob),
	}
}

type memoryWriter struct {
	store *memoryContentStore
	buf   *bytes.Buffer
	hash  hash.Hash
	off   int64
}

type streamWriter struct {
	store  *memoryContentStore
	blob   *streamBlob
	hash   hash.Hash
	off    int64
	closed bool
}

func (m *memoryContentStore) Writer(ctx context.Context, _ ...content.WriterOpt) (content.Writer, error) {
	if useStream, _ := ctx.Value(streamContextKey).(bool); useStream {
		pr, pw := io.Pipe()
		blob := &streamBlob{
			pr:        pr,
			pw:        pw,
			done:      make(chan struct{}),
			dataCache: new(bytes.Buffer),
		}
		return &streamWriter{
			store: m,
			blob:  blob,
			hash:  sha256.New(),
		}, nil
	}

	return &memoryWriter{
		store: m,
		buf:   new(bytes.Buffer),
		hash:  sha256.New(),
	}, nil
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	if n > 0 {
		w.hash.Write(p[:n])
		w.off += int64(n)
	}
	return n, err
}

func (w *memoryWriter) Close() error {
	return nil
}

func (w *memoryWriter) Commit(_ context.Context, _ int64, _ digest.Digest, _ ...content.Opt) error {
	dgst := digest.NewDigestFromBytes(digest.SHA256, w.hash.Sum(nil))

	blob := &memoryBlob{
		data:   w.buf.Bytes(),
		digest: dgst,
		size:   w.off,
	}

	w.store.mu.Lock()
	w.store.blobs[dgst] = blob
	w.store.mu.Unlock()

	return nil
}

func (w *memoryWriter) Truncate(_ int64) error {
	return nil
}

func (w *memoryWriter) Status() (content.Status, error) {
	return content.Status{
		Offset: w.off,
	}, nil
}

func (w *memoryWriter) Digest() digest.Digest {
	return digest.NewDigestFromBytes(digest.SHA256, w.hash.Sum(nil))
}

func (w *memoryWriter) Size() int64 {
	return w.off
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}

	n, err := w.blob.pw.Write(p)
	if n > 0 {
		w.hash.Write(p[:n])
		w.off += int64(n)

		w.blob.mu.Lock()
		w.blob.dataCache.Write(p[:n])
		w.blob.mu.Unlock()
	}
	return n, err
}

func (w *streamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.blob.pw.Close()
}

func (w *streamWriter) Commit(_ context.Context, size int64, expected digest.Digest, _ ...content.Opt) error {
	logrus.Infof("push stream data, size: %d bytes", w.off)

	w.blob.size = w.off
	w.blob.digest = digest.NewDigestFromBytes(digest.SHA256, w.hash.Sum(nil))

	if expected != "" && expected != w.blob.digest {
		logrus.Errorf("digest mismatch: expected %s, actual %s", expected, w.blob.digest)
		return fmt.Errorf("digest mismatch: expected %s, actual %s", expected, w.blob.digest)
	}

	if size > 0 && size != w.off {
		logrus.Warnf("size mismatch: expected %d, actual %d", size, w.off)
	}

	w.store.mu.Lock()
	w.store.streamBlobs[w.blob.digest] = w.blob
	w.store.mu.Unlock()

	close(w.blob.done)
	return nil
}

func (w *streamWriter) Truncate(_ int64) error {
	return nil
}

func (w *streamWriter) Status() (content.Status, error) {
	return content.Status{
		Offset: w.off,
	}, nil
}

func (w *streamWriter) Digest() digest.Digest {
	return w.blob.digest
}

func (w *streamWriter) Size() int64 {
	return w.off
}

type memoryReaderAt struct {
	data []byte
	size int64
}

func (r *memoryReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}

	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *memoryReaderAt) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}

	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (r *memoryReaderAt) Close() error {
	return nil
}

func (r *memoryReaderAt) Size() int64 {
	return r.size
}

type streamReaderAt struct {
	blob *streamBlob
	off  int64 // current read offset
}

func (r *streamReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.blob.mu.RLock()
	cachedData := r.blob.dataCache.Bytes()
	cachedSize := len(cachedData)
	r.blob.mu.RUnlock()

	if off >= int64(cachedSize) {
		select {
		case <-r.blob.done:
			return 0, io.EOF
		default:
			return 0, io.ErrUnexpectedEOF
		}
	}

	n := copy(p, cachedData[off:])

	if n < len(p) {
		select {
		case <-r.blob.done:
			if off+int64(n) >= r.blob.size {
				return n, io.EOF
			}
		default:
		}
	}

	return n, nil
}

func (r *streamReaderAt) Read(p []byte) (int, error) {
	n, err := r.blob.pr.Read(p)
	if n > 0 {
		r.off += int64(n)
	}
	return n, err
}

func (r *streamReaderAt) Close() error {
	return r.blob.pr.Close()
}

func (r *streamReaderAt) Size() int64 {
	select {
	case <-r.blob.done:
		return r.blob.size
	default:
		return 0 // size unknown
	}
}

func (m *memoryContentStore) ReaderAt(_ context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	m.mu.RLock()
	blob, ok := m.blobs[desc.Digest]
	if !ok {
		streamBlob, streamOk := m.streamBlobs[desc.Digest]
		m.mu.RUnlock()

		if streamOk {
			return &streamReaderAt{blob: streamBlob}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	m.mu.RUnlock()

	return &memoryReaderAt{data: blob.data, size: blob.size}, nil
}

func (m *memoryContentStore) Reader(_ context.Context, desc digest.Digest) (io.ReadCloser, error) {
	m.mu.RLock()
	blob, ok := m.blobs[desc]
	if !ok {
		streamBlob, streamOk := m.streamBlobs[desc]
		m.mu.RUnlock()

		if streamOk {
			return streamBlob.pr, nil
		}
		return nil, errdefs.ErrNotFound
	}
	m.mu.RUnlock()

	return io.NopCloser(bytes.NewReader(blob.data)), nil
}

func (m *memoryContentStore) Info(_ context.Context, dgst digest.Digest) (content.Info, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	blob, ok := m.blobs[dgst]
	if ok {
		return content.Info{
			Digest: dgst,
			Size:   blob.size,
		}, nil
	}

	streamBlob, streamOk := m.streamBlobs[dgst]
	if streamOk {
		return content.Info{
			Digest: dgst,
			Size:   streamBlob.size,
		}, nil
	}

	return content.Info{}, errdefs.ErrNotFound
}

func (m *memoryContentStore) Abort(_ context.Context, _ string) error {
	return nil
}

func (m *memoryContentStore) Status(_ context.Context, ref string) (content.Status, error) {
	return content.Status{Ref: ref}, nil
}

func (m *memoryContentStore) ListStatuses(_ context.Context, _ ...string) ([]content.Status, error) {
	return nil, nil
}

func (m *memoryContentStore) Delete(_ context.Context, dgst digest.Digest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.blobs, dgst)
	delete(m.streamBlobs, dgst)
	return nil
}

func (m *memoryContentStore) Update(_ context.Context, info content.Info, _ ...string) (content.Info, error) {
	return info, nil
}

func (m *memoryContentStore) Walk(_ context.Context, fn content.WalkFunc, _ ...string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for dgst, blob := range m.blobs {
		info := content.Info{
			Digest: dgst,
			Size:   blob.size,
		}
		if err := fn(info); err != nil {
			return err
		}
	}

	for dgst, blob := range m.streamBlobs {
		info := content.Info{
			Digest: dgst,
			Size:   blob.size,
		}
		if err := fn(info); err != nil {
			return err
		}
	}
	return nil
}
