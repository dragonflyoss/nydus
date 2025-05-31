package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"log"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

type memoryBlob struct {
	data   []byte
	digest digest.Digest
	size   int64
}

// streamBlob 支持流式传输的blob
type streamBlob struct {
	pr        *io.PipeReader
	pw        *io.PipeWriter
	digest    digest.Digest
	size      int64
	done      chan struct{}
	err       error
	dataCache *bytes.Buffer // 缓存已读取的数据，支持随机读取
	mu        sync.Mutex
}

type memoryContentStore struct {
	mu    sync.Mutex
	blobs map[digest.Digest]*memoryBlob
	// 支持流式传输的blobs
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

// streamWriter 支持流式传输的writer
type streamWriter struct {
	store  *memoryContentStore
	blob   *streamBlob
	hash   hash.Hash
	off    int64
	closed bool
}

func (m *memoryContentStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	if useStream, _ := ctx.Value("useStream").(bool); useStream {
		// 创建支持流式传输的writer
		pr, pw := io.Pipe()
		blob := &streamBlob{
			pr:        pr,
			pw:        pw,
			done:      make(chan struct{}),
			dataCache: new(bytes.Buffer),
		}
		w := &streamWriter{
			store: m,
			blob:  blob,
			hash:  sha256.New(),
		}
		return w, nil
	}

	// 原有的非流式writer
	w := &memoryWriter{
		store: m,
		buf:   new(bytes.Buffer),
		hash:  sha256.New(),
	}
	return w, nil
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

func (w *memoryWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
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

func (w *memoryWriter) Truncate(size int64) error {
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

// streamWriter的实现
func (w *streamWriter) Write(p []byte) (int, error) {
	logrus.Debugf("streamWriter: 正在写入 %d 字节的数据", len(p))
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := w.blob.pw.Write(p)
	if n > 0 {
		w.hash.Write(p[:n])
		w.off += int64(n)

		// 同时更新缓存，用于随机读取
		w.blob.mu.Lock()
		w.blob.dataCache.Write(p[:n])
		w.blob.mu.Unlock()

		logrus.Debugf("streamWriter: 成功写入 %d 字节，当前总计 %d 字节", n, w.off)
	}
	return n, err
}

func (w *streamWriter) Close() error {
	w.closed = true
	return w.blob.pw.Close()
}

func (w *streamWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	logrus.Infof("streamWriter: 提交数据，大小: %d 字节", w.off)
	w.blob.size = w.off
	w.blob.digest = digest.NewDigestFromBytes(digest.SHA256, w.hash.Sum(nil))

	logrus.Infof("streamWriter: 计算得到的摘要: %s", w.blob.digest)

	// 检查计算出的摘要与期望的摘要是否一致
	if expected != "" && expected != w.blob.digest {
		logrus.Errorf("streamWriter: 摘要不匹配，期望: %s, 计算得到: %s", expected, w.blob.digest)
		return fmt.Errorf("unexpected digest: %s, expected: %s", w.blob.digest, expected)
	}

	// 检查实际大小与期望大小是否一致
	if size > 0 && size != w.off {
		logrus.Errorf("streamWriter: 大小不匹配，期望: %d, 实际: %d", size, w.off)
		return fmt.Errorf("unexpected size %d, expected %d", w.off, size)
	}

	w.store.mu.Lock()
	w.store.streamBlobs[w.blob.digest] = w.blob
	w.store.mu.Unlock()

	close(w.blob.done)
	return nil
}

func (w *streamWriter) Truncate(size int64) error {
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

// streamReaderAt 支持流式传输的reader
type streamReaderAt struct {
	blob *streamBlob
	off  int64 // 当前已读取的位置
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

// streamReaderAt的实现
func (r *streamReaderAt) ReadAt(p []byte, off int64) (int, error) {
	logrus.Debugf("streamReaderAt: 请求从偏移量 %d 读取 %d 字节", off, len(p))

	r.blob.mu.Lock()
	cachedData := r.blob.dataCache.Bytes()
	cachedSize := len(cachedData)
	r.blob.mu.Unlock()

	logrus.Debugf("streamReaderAt: 当前缓存大小: %d 字节", cachedSize)

	if off >= int64(cachedSize) {
		// 如果请求的偏移超出已缓存数据，需要等待更多数据写入
		select {
		case <-r.blob.done:
			// 流已经结束，但请求的偏移仍然超出范围
			logrus.Debugf("streamReaderAt: 流已结束，但请求的偏移量超出范围")
			return 0, io.EOF
		default:
			// 返回错误，表示需要等待更多数据
			logrus.Debugf("streamReaderAt: 等待更多数据")
			return 0, io.ErrUnexpectedEOF
		}
	}

	n := copy(p, cachedData[off:])
	logrus.Debugf("streamReaderAt: 已读取 %d 字节数据", n)

	if n < len(p) && off+int64(n) >= r.blob.size {
		// 已读取到末尾
		logrus.Debugf("streamReaderAt: 已达到数据末尾")
		return n, io.EOF
	}
	return n, nil
}

func (r *streamReaderAt) Read(p []byte) (int, error) {
	logrus.Debugf("streamReaderAt.Read: 尝试读取 %d 字节", len(p))
	n, err := r.blob.pr.Read(p)
	if n > 0 {
		r.off += int64(n)
		logrus.Debugf("streamReaderAt.Read: 成功读取 %d 字节，当前总计 %d 字节", n, r.off)
	}
	if err != nil {
		logrus.Debugf("streamReaderAt.Read: 读取时发生错误: %v", err)
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
		return 0 // 如果流未结束，返回0表示尚未知道大小
	}
}

func (m *memoryContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	m.mu.Lock()
	blob, ok := m.blobs[desc.Digest]
	if !ok {
		// 如果在普通blob中找不到，尝试在流式blob中查找
		streamBlob, streamOk := m.streamBlobs[desc.Digest]
		m.mu.Unlock()
		if streamOk {
			return &streamReaderAt{blob: streamBlob}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	m.mu.Unlock()
	return &memoryReaderAt{data: blob.data, size: blob.size}, nil
}

func (m *memoryContentStore) Reader(ctx context.Context, desc digest.Digest) (io.ReadCloser, error) {
	m.mu.Lock()
	blob, ok := m.blobs[desc]
	if !ok {
		// 如果在普通blob中找不到，尝试在流式blob中查找
		streamBlob, streamOk := m.streamBlobs[desc]
		m.mu.Unlock()
		if streamOk {
			return streamBlob.pr, nil
		}
		return nil, errdefs.ErrNotFound
	}
	m.mu.Unlock()
	return io.NopCloser(bytes.NewReader(blob.data)), nil
}

func (m *memoryContentStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blob, ok := m.blobs[dgst]
	if !ok {
		// 如果在普通blob中找不到，尝试在流式blob中查找
		streamBlob, streamOk := m.streamBlobs[dgst]
		if streamOk {
			return content.Info{
				Digest: dgst,
				Size:   streamBlob.size,
			}, nil
		}
		return content.Info{}, errdefs.ErrNotFound
	}
	return content.Info{
		Digest: dgst,
		Size:   blob.size,
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
	delete(m.streamBlobs, dgst)
	return nil
}

func (m *memoryContentStore) Update(ctx context.Context, info content.Info, fieldpaths ...string) (content.Info, error) {
	return info, nil
}

func (m *memoryContentStore) Walk(ctx context.Context, fn content.WalkFunc, filters ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 遍历普通blob
	for dgst, blob := range m.blobs {
		info := content.Info{
			Digest: dgst,
			Size:   blob.size,
		}
		if err := fn(info); err != nil {
			return err
		}
	}

	// 遍历流式blob
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
