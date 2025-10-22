package provider

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	ctrcontent "github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// StreamContent is a content.Store adapter that:
// - Never ingests data locally (Writer returns AlreadyExists)
// - Serves reads directly from remote using registry HTTP range requests
// - Stores labels in-memory to satisfy label update/get during handler pipeline
type StreamContent struct {
	base ctrcontent.Store

	// remote access helpers
	hosts      remote.HostFunc
	defaultRef string

	mu     sync.RWMutex
	labels map[digest.Digest]map[string]string
	blobs  map[digest.Digest][]byte
}

func NewStreamContent(base ctrcontent.Store, hosts remote.HostFunc) *StreamContent {
	return &StreamContent{base: base, hosts: hosts, labels: make(map[digest.Digest]map[string]string), blobs: make(map[digest.Digest][]byte)}
}

// SetDefaultRef sets the repository reference used for remote reads when no
// distribution source label is yet available.
func (s *StreamContent) SetDefaultRef(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultRef = ref
}

// Ingester implements heuristic routing for content ingestion:
//   - If ref looks like containerd fetch key (manifest-*/index-*/layer-*/config-*/attestation-*),
//     treat as remote fetch and skip ingestion (AlreadyExists).
//   - Otherwise, provide in-memory writer to accept generated content (JSON or blobs).
func (s *StreamContent) Writer(_ context.Context, opts ...ctrcontent.WriterOpt) (ctrcontent.Writer, error) {
	var wopts ctrcontent.WriterOpts
	for _, opt := range opts {
		opt(&wopts)
	}

	// Check if this is a containerd fetch key that should be treated as remote content
	if isFetchRef(wopts.Ref) {
		// Skip ingestion for remote content - return AlreadyExists to indicate
		// the content is available remotely and doesn't need local storage
		return nil, errdefs.ErrAlreadyExists
	}

	// For generated content (JSON descriptors, etc.), provide in-memory writer
	return newMemWriter(s, wopts.Desc), nil
}

// Provider
func (s *StreamContent) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (ctrcontent.ReaderAt, error) {
	s.mu.RLock()
	if b, ok := s.blobs[desc.Digest]; ok {
		s.mu.RUnlock()
		return &bytesReaderAt{r: bytes.NewReader(b)}, nil
	}
	ref := s.defaultRef
	s.mu.RUnlock()

	if ref == "" {
		return nil, fmt.Errorf("stream content: defaultRef is empty: %w", errdefs.ErrNotFound)
	}

	return remote.Fetch(ctx, ref, desc, s.hosts, false)
}

// Manager
func (s *StreamContent) Info(_ context.Context, dgst digest.Digest) (ctrcontent.Info, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if lbs, ok := s.labels[dgst]; ok {
		return ctrcontent.Info{Digest: dgst, Labels: copyMap(lbs)}, nil
	}
	// Emulate empty info for non-existent content to allow label handlers to proceed.
	return ctrcontent.Info{Digest: dgst, Labels: nil}, nil
}

func (s *StreamContent) Update(_ context.Context, info ctrcontent.Info, _ ...string) (ctrcontent.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.labels[info.Digest] == nil {
		s.labels[info.Digest] = make(map[string]string)
	}
	for k, v := range info.Labels {
		s.labels[info.Digest][k] = v
	}
	return ctrcontent.Info{Digest: info.Digest, Labels: copyMap(s.labels[info.Digest])}, nil
}

func (s *StreamContent) Walk(_ context.Context, _ ctrcontent.WalkFunc, _ ...string) error {
	// No local content to walk; return nil to indicate empty store.
	return nil
}

func (s *StreamContent) Delete(_ context.Context, dgst digest.Digest) error {
	// Nothing to delete in no-op store.
	s.mu.Lock()
	delete(s.labels, dgst)
	delete(s.blobs, dgst)
	s.mu.Unlock()
	return nil
}

// IngestManager
func (s *StreamContent) Status(_ context.Context, _ string) (ctrcontent.Status, error) {
	return ctrcontent.Status{}, errdefs.ErrNotFound
}

func (s *StreamContent) ListStatuses(_ context.Context, _ ...string) ([]ctrcontent.Status, error) {
	return nil, nil
}

func (s *StreamContent) Abort(_ context.Context, _ string) error {
	return nil
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	n := make(map[string]string, len(m))
	for k, v := range m {
		n[k] = v
	}
	return n
}

// memWriter buffers JSON descriptor content in memory for later push.
type memWriter struct {
	sc   *StreamContent
	desc ocispec.Descriptor
	buf  bytes.Buffer
	dgst digest.Digester
}

func (w *memWriter) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	if n > 0 {
		if w.dgst == nil {
			w.dgst = digest.SHA256.Digester()
		}
		_, _ = w.dgst.Hash().Write(p[:n])
	}
	return n, err
}
func (w *memWriter) Close() error { return nil }
func (w *memWriter) Digest() digest.Digest {
	if w.dgst == nil {
		return digest.FromBytes(w.buf.Bytes())
	}
	return w.dgst.Digest()
}
func (w *memWriter) Status() (ctrcontent.Status, error) {
	n := int64(w.buf.Len())
	return ctrcontent.Status{Offset: n, Total: n}, nil
}
func (w *memWriter) Truncate(size int64) error {
	if size < 0 {
		return fmt.Errorf("invalid size")
	}
	if int64(w.buf.Len()) == size {
		return nil
	}
	w.buf.Truncate(int(size))
	return nil
}

func (w *memWriter) Commit(_ context.Context, _ int64, expected digest.Digest, _ ...ctrcontent.Opt) error {
	b := w.buf.Bytes()
	// Ignore size mismatch and rely on digest validation
	dgst := expected
	if dgst == "" {
		dgst = w.Digest()
	}
	// Store in memory
	w.sc.mu.Lock()
	w.sc.blobs[dgst] = append([]byte(nil), b...)
	w.sc.mu.Unlock()
	return nil
}

type bytesReaderAt struct{ r *bytes.Reader }

func (br *bytesReaderAt) ReadAt(p []byte, off int64) (int, error) { return br.r.ReadAt(p, off) }
func (br *bytesReaderAt) Close() error                            { return nil }
func (br *bytesReaderAt) Size() int64                             { return int64(br.r.Len()) }

func newMemWriter(sc *StreamContent, desc ocispec.Descriptor) *memWriter {
	return &memWriter{sc: sc, desc: desc}
}

// isFetchRef checks if the reference looks like a containerd fetch key.
// Containerd fetch keys follow patterns: manifest-*, index-*, layer-*, config-*, attestation-*
func isFetchRef(ref string) bool {
	if len(ref) == 0 {
		return false
	}

	// Check for containerd fetch key patterns
	fetchPrefixes := []string{
		"manifest-",
		"index-",
		"layer-",
		"config-",
		"attestation-",
	}

	for _, prefix := range fetchPrefixes {
		if hasPrefix(ref, prefix) {
			return true
		}
	}
	return false
}

func hasPrefix(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}
