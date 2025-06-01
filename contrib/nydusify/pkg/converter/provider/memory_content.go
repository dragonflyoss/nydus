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

// memoryBlob 表示内存中存储的完整内容
type memoryBlob struct {
	data   []byte
	digest digest.Digest
	size   int64
}

// streamBlob 支持流式传输的blob
type streamBlob struct {
	pr        *io.PipeReader // 用于流式读取的管道
	pw        *io.PipeWriter // 用于流式写入的管道
	digest    digest.Digest  // 内容的摘要
	size      int64          // 内容的大小
	done      chan struct{}  // 传输完成信号
	dataCache *bytes.Buffer  // 缓存已读取的数据，支持随机读取
	mu        sync.RWMutex   // 保护数据缓存的互斥锁
}

// memoryContentStore 实现了内存中的内容存储
type memoryContentStore struct {
	mu          sync.RWMutex
	blobs       map[digest.Digest]*memoryBlob
	streamBlobs map[digest.Digest]*streamBlob
}

// NewMemoryContentStore 创建新的内存内容存储
func NewMemoryContentStore() content.Store {
	return &memoryContentStore{
		blobs:       make(map[digest.Digest]*memoryBlob),
		streamBlobs: make(map[digest.Digest]*streamBlob),
	}
}

// memoryWriter 用于写入普通内容
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

// Writer 根据上下文创建合适的writer
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
		return &streamWriter{
			store: m,
			blob:  blob,
			hash:  sha256.New(),
		}, nil
	}

	// 原有的非流式writer
	return &memoryWriter{
		store: m,
		buf:   new(bytes.Buffer),
		hash:  sha256.New(),
	}, nil
}

// memoryWriter的实现 ========================================

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

// streamWriter的实现 ========================================

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}

	// 写入管道
	n, err := w.blob.pw.Write(p)
	if n > 0 {
		// 更新哈希和偏移量
		w.hash.Write(p[:n])
		w.off += int64(n)

		// 同时更新缓存，用于随机读取
		w.blob.mu.Lock()
		w.blob.dataCache.Write(p[:n])
		w.blob.mu.Unlock()

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.Debugf("流式写入: %d 字节，总计: %d 字节", n, w.off)
		}
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

func (w *streamWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	logrus.Infof("提交流式数据，大小: %d 字节", w.off)

	// 设置blob属性
	w.blob.size = w.off
	w.blob.digest = digest.NewDigestFromBytes(digest.SHA256, w.hash.Sum(nil))

	// 检查摘要
	if expected != "" && expected != w.blob.digest {
		logrus.Errorf("摘要不匹配: 期望 %s, 计算得到 %s", expected, w.blob.digest)
		return fmt.Errorf("摘要不匹配: 期望 %s, 计算得到 %s", expected, w.blob.digest)
	}

	// 检查大小
	if size > 0 && size != w.off {
		logrus.Warnf("大小不匹配: 期望 %d, 实际 %d", size, w.off)
	}

	// 添加到存储
	w.store.mu.Lock()
	w.store.streamBlobs[w.blob.digest] = w.blob
	w.store.mu.Unlock()

	// 标记完成
	close(w.blob.done)
	logrus.Infof("成功提交流式数据，摘要: %s", w.blob.digest)
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

// memoryReaderAt 用于随机读取普通内容 ==============================

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

// streamReaderAt 支持流式传输的随机读取器 ============================

type streamReaderAt struct {
	blob *streamBlob
	off  int64 // 当前已读取的位置
}

func (r *streamReaderAt) ReadAt(p []byte, off int64) (int, error) {
	// 获取当前缓存数据的只读视图
	r.blob.mu.RLock()
	cachedData := r.blob.dataCache.Bytes()
	cachedSize := len(cachedData)
	r.blob.mu.RUnlock()

	// 检查偏移量是否超出缓存范围
	if off >= int64(cachedSize) {
		select {
		case <-r.blob.done:
			// 如果已完成但偏移量仍超出范围，返回EOF
			return 0, io.EOF
		default:
			// 数据还在传输中，等待更多数据
			return 0, io.ErrUnexpectedEOF
		}
	}

	// 复制可用数据
	n := copy(p, cachedData[off:])

	// 检查是否已读取到末尾
	if n < len(p) {
		select {
		case <-r.blob.done:
			// 如果已完成并且读取到末尾，返回EOF
			if off+int64(n) >= r.blob.size {
				return n, io.EOF
			}
		default:
			// 数据还在传输中
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
		return 0 // 传输未完成，大小未知
	}
}

// ReaderAt 创建内容的随机读取器 ====================================

func (m *memoryContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	// 先使用读锁尝试查找
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

// 其余方法实现 ==================================================

func (m *memoryContentStore) Reader(ctx context.Context, desc digest.Digest) (io.ReadCloser, error) {
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

func (m *memoryContentStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
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
	m.mu.RLock()
	defer m.mu.RUnlock()

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
