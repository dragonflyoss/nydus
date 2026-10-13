package remote

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestPushRetriesDeferredIndex(t *testing.T) {
	testPushRetriesDeferred(t, ocispec.MediaTypeImageIndex)
}

func TestPushRetriesDeferredManifest(t *testing.T) {
	testPushRetriesDeferred(t, ocispec.MediaTypeImageManifest)
}

func testPushRetriesDeferred(t *testing.T, mediaType string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		data := []byte(`{"schemaVersion":2,"manifests":[]}`)
		contents := map[digest.Digest][]byte{}
		if mediaType == ocispec.MediaTypeImageManifest {
			configData := []byte(`{}`)
			config := contentTestDescriptor(ocispec.MediaTypeImageConfig, configData)
			contents[config.Digest] = configData
			manifest := ocispec.Manifest{Config: config}
			manifest.SchemaVersion = 2
			var err error
			data, err = json.Marshal(manifest)
			require.NoError(t, err)
		}
		desc := contentTestDescriptor(mediaType, data)
		contents[desc.Digest] = data
		pusher := &contentTestPusher{commitErr: syscall.ECONNRESET, failDigest: desc.Digest}
		store := &contentTestStore{contents: contents}

		err := push(context.Background(), store, contentTestResolver{pusher: pusher}, desc, "example.test/image:tag", platforms.All, nil)
		require.NoError(t, err)
		attempts := 0
		for _, writer := range pusher.writers {
			if writer.desc.Digest == desc.Digest {
				attempts++
				require.Equal(t, data, writer.Bytes())
			}
		}
		require.Equal(t, 2, attempts)
		assertContentTestClosed(t, pusher, store)
	})
}

func TestPushDoesNotRetrySourceOpenError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sourceErr := errors.New("source is unreadable")
		store := &contentTestStore{openErr: sourceErr}
		pusher := &contentTestPusher{}
		desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromString("layer"), Size: 5}

		err := push(ctx, store, contentTestResolver{pusher: pusher}, desc, "example.test/image:tag", platforms.All, nil)
		require.ErrorIs(t, err, sourceErr)
		require.Equal(t, 1, store.opens)
		require.Len(t, pusher.writers, 1)
		require.Equal(t, 1, pusher.writers[0].closes)
		require.NoError(t, ctx.Err())
	})
}

func TestPushHonorsHandlerWrapper(t *testing.T) {
	configData := []byte(`{}`)
	config := contentTestDescriptor(ocispec.MediaTypeImageConfig, configData)
	layer := contentTestDescriptor(ocispec.MediaTypeImageLayer, []byte("external layer"))
	manifest := ocispec.Manifest{Config: config, Layers: []ocispec.Descriptor{layer}}
	manifest.SchemaVersion = 2
	manifestData, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDesc := contentTestDescriptor(ocispec.MediaTypeImageManifest, manifestData)
	store := &contentTestStore{contents: map[digest.Digest][]byte{
		config.Digest:       configData,
		manifestDesc.Digest: manifestData,
	}}
	pusher := &contentTestPusher{}
	wrapper := func(h images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if desc.Digest == layer.Digest {
				return nil, images.ErrSkipDesc
			}
			return h.Handle(ctx, desc)
		})
	}

	err = push(
		context.Background(),
		store,
		contentTestResolver{pusher: pusher},
		manifestDesc,
		"example.test/image:tag",
		platforms.All,
		wrapper,
	)
	require.NoError(t, err)
	require.Equal(t, 2, pusher.calls)
	for _, writer := range pusher.writers {
		require.NotEqual(t, layer.Digest, writer.desc.Digest)
	}
	assertContentTestClosed(t, pusher, store)
}

func TestPushRetriesRemoteFailures(t *testing.T) {
	for _, phase := range []string{"open", "write", "commit"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				data := bytes.Repeat([]byte("layer"), 20000)
				store := &contentTestStore{data: data}
				pusher := &contentTestPusher{}
				remoteErr := &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET}
				switch phase {
				case "open":
					pusher.pushErr = remoteErr
				case "write":
					pusher.writeErr = remoteErr
				case "commit":
					pusher.commitErr = remoteErr
				}
				err := push(context.Background(), store, contentTestResolver{pusher: pusher}, contentTestDescriptor(ocispec.MediaTypeImageLayer, data), "example.test/image:tag", platforms.All, nil)
				require.NoError(t, err)
				require.Equal(t, 2, pusher.calls)
				require.Equal(t, 1, store.opens)
				require.Equal(t, data, pusher.writers[len(pusher.writers)-1].Bytes())
				if phase == "write" {
					require.Equal(t, data[:len(data)/2], pusher.writers[0].Bytes())
				}
				if phase != "open" {
					require.Equal(t, []int64{0, 0}, store.readers[0].offsets)
				}
				assertContentTestClosed(t, pusher, store)
			})
		})
	}
}

func TestPushRetryLimit(t *testing.T) {
	for _, phase := range []string{"open", "write", "commit", "reset"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				data := []byte("layer")
				store := &contentTestStore{data: data}
				pusher := &contentTestPusher{alwaysFail: true}
				remoteErr := remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusServiceUnavailable}
				switch phase {
				case "open":
					pusher.pushErr = remoteErr
				case "write":
					pusher.writeErr = remoteErr
				case "commit":
					pusher.commitErr = remoteErr
				case "reset":
					pusher.commitErr = content.ErrReset
				}
				err := push(context.Background(), store, contentTestResolver{pusher: pusher}, contentTestDescriptor(ocispec.MediaTypeImageLayer, data), "example.test/image:tag", platforms.All, nil)
				if phase == "reset" {
					require.ErrorContains(t, err, "push reset retry limit exceeded")
					require.NotErrorIs(t, err, content.ErrReset)
					require.Equal(t, 1, pusher.calls)
					require.Equal(t, pushRetries, pusher.writers[0].commits)
				} else {
					require.Error(t, err)
					var status remoteserrors.ErrUnexpectedStatus
					require.ErrorAs(t, err, &status)
					require.Equal(t, http.StatusServiceUnavailable, status.StatusCode)
					require.Equal(t, pushRetries, pusher.calls)
				}
				assertContentTestClosed(t, pusher, store)
			})
		})
	}
}

func TestPushDoesNotRetryPermanentErrors(t *testing.T) {
	for _, phase := range []string{"open", "write", "commit", "source-open", "source-read"} {
		t.Run(phase, func(t *testing.T) {
			data := []byte("layer")
			store := &contentTestStore{data: data}
			pusher := &contentTestPusher{alwaysFail: true}
			permanentErr := errors.New("permanent failure")
			switch phase {
			case "open":
				pusher.pushErr = permanentErr
			case "write":
				pusher.writeErr = permanentErr
			case "commit":
				pusher.commitErr = permanentErr
			case "source-open":
				store.openErr = permanentErr
			case "source-read":
				store.readErr = permanentErr
			}
			err := push(context.Background(), store, contentTestResolver{pusher: pusher}, contentTestDescriptor(ocispec.MediaTypeImageLayer, data), "example.test/image:tag", platforms.All, nil)
			require.ErrorIs(t, err, permanentErr)
			require.Equal(t, 1, pusher.calls)
			assertContentTestClosed(t, pusher, store)
		})
	}
}

func TestPushDoesNotRetryNetworkLikeSourceErrors(t *testing.T) {
	for _, phase := range []string{"open", "read"} {
		t.Run(phase, func(t *testing.T) {
			data := []byte("layer")
			store := &contentTestStore{data: data}
			pusher := &contentTestPusher{}
			sourceErr := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
			if phase == "open" {
				store.openErr = sourceErr
			} else {
				store.readErr = sourceErr
			}
			err := push(context.Background(), store, contentTestResolver{pusher: pusher}, contentTestDescriptor(ocispec.MediaTypeImageLayer, data), "example.test/image:tag", platforms.All, nil)
			require.ErrorIs(t, err, sourceErr)
			require.Equal(t, 1, pusher.calls)
			assertContentTestClosed(t, pusher, store)
		})
	}
}

func TestPushCancellation(t *testing.T) {
	for _, phase := range []string{"before-open", "open", "write", "commit", "backoff"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				data := []byte("layer")
				store := &contentTestStore{data: data}
				pusher := &contentTestPusher{}
				waitForCancel := func(ctx context.Context) error {
					<-ctx.Done()
					return syscall.ECONNRESET
				}
				switch phase {
				case "before-open":
					cancel()
				case "open":
					pusher.onPush = waitForCancel
				case "write":
					pusher.onWrite = waitForCancel
				case "commit":
					pusher.onCommit = waitForCancel
				case "backoff":
					pusher.commitErr = syscall.ECONNRESET
				}
				done := make(chan error, 1)
				go func() {
					done <- push(ctx, store, contentTestResolver{pusher: pusher}, contentTestDescriptor(ocispec.MediaTypeImageLayer, data), "example.test/image:tag", platforms.All, nil)
				}()
				synctest.Wait()
				cancel()
				require.ErrorIs(t, <-done, context.Canceled)
				if phase == "before-open" {
					require.Zero(t, pusher.calls)
				} else {
					require.Equal(t, 1, pusher.calls)
				}
				assertContentTestClosed(t, pusher, store)
			})
		})
	}
}

func TestRetryPusherSerializesWriters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pusher := &contentTestPusher{}
		retrying := &retryPusher{pusher: pusher}
		desc := contentTestDescriptor(ocispec.MediaTypeImageLayer, []byte("layer"))
		first, err := retrying.Push(context.Background(), desc)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := retrying.Push(ctx, desc)
			done <- err
		}()
		synctest.Wait()
		require.Equal(t, 1, pusher.calls)
		cancel()
		require.ErrorIs(t, <-done, context.Canceled)
		require.NoError(t, first.Close())
		require.NoError(t, first.Close())
		second, err := retrying.Push(context.Background(), desc)
		require.NoError(t, err)
		require.NoError(t, second.Close())
		require.Equal(t, 2, pusher.calls)
		assertContentTestClosed(t, pusher, &contentTestStore{})
	})
}

func TestIsTransientPushError(t *testing.T) {
	uploadError := func(code string) error {
		return remoteserrors.ErrUnexpectedStatus{
			StatusCode: http.StatusNotFound, RequestMethod: http.MethodPut,
			RequestURL: "https://example.test/v2/image/blobs/uploads/session",
			Body:       []byte(fmt.Sprintf(`{"errors":[{"code":%q}]}`, code)),
		}
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"exists", errdefs.ErrAlreadyExists, false},
		{"unavailable", errdefs.ErrUnavailable, false},
		{"invalid", errdefs.ErrInvalidArgument, false},
		{"permission", syscall.EACCES, false},
		{"certificate", x509.UnknownAuthorityError{}, false},
		{"dns-missing", &net.DNSError{IsNotFound: true}, false},
		{"dns-timeout", &net.DNSError{IsTimeout: true}, true},
		{"dns-temporary", &net.DNSError{IsTemporary: true}, true},
		{"dns-wrapped", &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{IsTemporary: true}}, true},
		{"reset", &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET}, true},
		{"broken-pipe", syscall.EPIPE, true},
		{"unexpected-eof", io.ErrUnexpectedEOF, true},
		{"eof", io.EOF, true},
		{"closed-pipe", io.ErrClosedPipe, false},
		{"upload-invalid", uploadError("BLOB_UPLOAD_INVALID"), true},
		{"upload-unknown", uploadError("BLOB_UPLOAD_UNKNOWN"), true},
		{"blob-unknown", uploadError("BLOB_UNKNOWN"), false},
		{"message-only", errors.New("503 Service Unavailable"), false},
	}
	for _, code := range []int{400, 401, 403, 404, 408, 429, 500, 501, 502, 503, 504} {
		tests = append(tests, struct {
			name string
			err  error
			want bool
		}{fmt.Sprintf("http-%d", code), remoteserrors.ErrUnexpectedStatus{StatusCode: code}, code == 408 || code == 429 || code == 500 || code == 502 || code == 503 || code == 504})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, isTransientPushError(test.err))
			if test.err != nil {
				require.Equal(t, test.want, isTransientPushError(fmt.Errorf("wrapped: %w", test.err)))
			}
		})
	}
}

func contentTestDescriptor(mediaType string, data []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

func assertContentTestClosed(t *testing.T, pusher *contentTestPusher, store *contentTestStore) {
	t.Helper()
	require.Zero(t, pusher.ingesterCalls)
	for _, writer := range pusher.writers {
		require.Equal(t, 1, writer.closes)
	}
	for _, ctx := range pusher.contexts {
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	}
	for _, reader := range store.readers {
		require.Equal(t, 1, reader.closes)
	}
}

type contentTestResolver struct {
	remotes.Resolver
	pusher remotes.Pusher
}

func (resolver contentTestResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return resolver.pusher, nil
}

type contentTestStore struct {
	content.Store
	mu       sync.Mutex
	data     []byte
	contents map[digest.Digest][]byte
	openErr  error
	readErr  error
	opens    int
	readers  []*contentTestReader
}

func (store *contentTestStore) ReaderAt(_ context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.opens++
	if store.openErr != nil {
		return nil, store.openErr
	}
	data := store.data
	if store.contents != nil {
		data = store.contents[desc.Digest]
	}
	reader := &contentTestReader{Reader: bytes.NewReader(data), readErr: store.readErr}
	store.readers = append(store.readers, reader)
	return reader, nil
}

func (store *contentTestStore) Info(context.Context, digest.Digest) (content.Info, error) {
	return content.Info{}, errdefs.ErrNotFound
}

type contentTestReader struct {
	*bytes.Reader
	readErr error
	offsets []int64
	closes  int
}

func (reader *contentTestReader) ReadAt(data []byte, offset int64) (int, error) {
	reader.offsets = append(reader.offsets, offset)
	read, err := reader.Reader.ReadAt(data, offset)
	if reader.readErr != nil {
		return read, reader.readErr
	}
	return read, err
}

func (reader *contentTestReader) Close() error {
	reader.closes++
	return nil
}

type contentTestPusher struct {
	mu            sync.Mutex
	writers       []*contentTestWriter
	contexts      []context.Context
	calls         int
	ingesterCalls int
	failures      int
	active        bool
	alwaysFail    bool
	failDigest    digest.Digest
	pushErr       error
	writeErr      error
	commitErr     error
	onPush        func(context.Context) error
	onWrite       func(context.Context) error
	onCommit      func(context.Context) error
}

func (pusher *contentTestPusher) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	pusher.mu.Lock()
	pusher.ingesterCalls++
	if pusher.active {
		pusher.mu.Unlock()
		return nil, errdefs.ErrUnavailable
	}
	pusher.mu.Unlock()
	var options content.WriterOpts
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}
	return pusher.Push(ctx, options.Desc)
}

func (pusher *contentTestPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	pusher.mu.Lock()
	defer pusher.mu.Unlock()
	pusher.calls++
	pusher.contexts = append(pusher.contexts, ctx)
	if pusher.onPush != nil {
		if err := pusher.onPush(ctx); err != nil {
			return nil, err
		}
	}
	writer := &contentTestWriter{pusher: pusher, desc: desc, ctx: ctx}
	if (pusher.failDigest == "" || pusher.failDigest == desc.Digest) && (pusher.alwaysFail || pusher.failures == 0) {
		pusher.failures++
		if pusher.pushErr != nil {
			return nil, pusher.pushErr
		}
		writer.writeErr, writer.commitErr = pusher.writeErr, pusher.commitErr
	}
	pusher.writers = append(pusher.writers, writer)
	pusher.active = true
	return writer, nil
}

type contentTestWriter struct {
	bytes.Buffer
	pusher    *contentTestPusher
	desc      ocispec.Descriptor
	ctx       context.Context
	writeErr  error
	commitErr error
	closes    int
	commits   int
}

func (writer *contentTestWriter) Write(data []byte) (int, error) {
	if writer.pusher.onWrite != nil {
		if err := writer.pusher.onWrite(writer.ctx); err != nil {
			return 0, err
		}
	}
	if writer.writeErr != nil {
		written, _ := writer.Buffer.Write(data[:len(data)/2])
		return written, writer.writeErr
	}
	return writer.Buffer.Write(data)
}

func (writer *contentTestWriter) Close() error {
	writer.closes++
	writer.pusher.mu.Lock()
	defer writer.pusher.mu.Unlock()
	if writer.Len() > 0 {
		writer.pusher.active = false
	}
	return nil
}

func (writer *contentTestWriter) Status() (content.Status, error) {
	return content.Status{Offset: int64(writer.Len()), Total: writer.desc.Size}, nil
}

func (writer *contentTestWriter) Digest() digest.Digest { return writer.desc.Digest }

func (writer *contentTestWriter) Commit(context.Context, int64, digest.Digest, ...content.Opt) error {
	writer.commits++
	if writer.pusher.onCommit != nil {
		if err := writer.pusher.onCommit(writer.ctx); err != nil {
			return err
		}
	}
	if errors.Is(writer.commitErr, content.ErrReset) {
		writer.Reset()
	}
	return writer.commitErr
}

func (writer *contentTestWriter) Truncate(size int64) error {
	writer.Buffer.Truncate(int(size))
	return nil
}
