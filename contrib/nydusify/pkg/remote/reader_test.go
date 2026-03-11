package remote

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockNamed struct {
	mockName   string
	mockString string
}

func (m *MockNamed) Name() string {
	return m.mockName
}
func (m *MockNamed) String() string {
	return m.mockString
}

// MockResolver implements the Resolver interface for testing purposes.
type MockResolver struct {
	ResolveFunc         func(ctx context.Context, ref string) (string, ocispec.Descriptor, error)
	FetcherFunc         func(ctx context.Context, ref string) (remotes.Fetcher, error)
	PusherFunc          func(ctx context.Context, ref string) (remotes.Pusher, error)
	PusherInChunkedFunc func(ctx context.Context, ref string) (remotes.PusherInChunked, error)
}

// Resolve implements the Resolver.Resolve method.
func (m *MockResolver) Resolve(ctx context.Context, ref string) (string, ocispec.Descriptor, error) {
	if m.ResolveFunc != nil {
		return m.ResolveFunc(ctx, ref)
	}
	return "", ocispec.Descriptor{}, errors.New("ResolveFunc not implemented")
}

// Fetcher implements the Resolver.Fetcher method.
func (m *MockResolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	if m.FetcherFunc != nil {
		return m.FetcherFunc(ctx, ref)
	}
	return nil, errors.New("FetcherFunc not implemented")
}

// Pusher implements the Resolver.Pusher method.
func (m *MockResolver) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	if m.PusherFunc != nil {
		return m.PusherFunc(ctx, ref)
	}
	return nil, errors.New("PusherFunc not implemented")
}

// PusherInChunked implements the Resolver.PusherInChunked method.
func (m *MockResolver) PusherInChunked(ctx context.Context, ref string) (remotes.PusherInChunked, error) {
	if m.PusherInChunkedFunc != nil {
		return m.PusherInChunkedFunc(ctx, ref)
	}
	return nil, errors.New("PusherInChunkedFunc not implemented")
}

type mockReadSeekCloeser struct {
	buf bytes.Buffer
}

func (m *mockReadSeekCloeser) Read(p []byte) (n int, err error) {
	return m.buf.Read(p)
}

func (m *mockReadSeekCloeser) Seek(int64, int) (int64, error) {
	return 0, nil
}

func (m *mockReadSeekCloeser) Close() error {
	return nil
}

func TestReadSeekCloser(t *testing.T) {
	remote := &Remote{
		parsed: &MockNamed{
			mockName:   "docker.io/library/busybox:latest",
			mockString: "docker.io/library/busybox:latest",
		},
	}
	t.Run("Run not ReadSeekCloser", func(t *testing.T) {
		remote.resolverFunc = func(bool) remotes.Resolver {
			return &MockResolver{
				FetcherFunc: func(context.Context, string) (remotes.Fetcher, error) {
					var buf bytes.Buffer
					return remotes.FetcherFunc(func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
						// return io.ReadSeekCloser
						return &readerAt{
							Reader: &buf,
							Closer: io.NopCloser(&buf),
						}, nil
					}), nil
				},
			}
		}
		_, err := remote.ReadSeekCloser(context.Background(), ocispec.Descriptor{}, false)
		assert.Error(t, err)
	})

	t.Run("Run Normal", func(t *testing.T) {
		// mock io.ReadSeekCloser
		remote.resolverFunc = func(bool) remotes.Resolver {
			return &MockResolver{
				FetcherFunc: func(context.Context, string) (remotes.Fetcher, error) {
					var buf bytes.Buffer
					return remotes.FetcherFunc(func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
						return &mockReadSeekCloeser{
							buf: buf,
						}, nil
					}), nil
				},
			}
		}
		rsc, err := remote.ReadSeekCloser(context.Background(), ocispec.Descriptor{}, false)
		assert.NoError(t, err)
		assert.NotNil(t, rsc)
	})
}

type readOnlyBuffer struct {
	buf bytes.Buffer
}

func (r *readOnlyBuffer) Read(p []byte) (int, error) {
	return r.buf.Read(p)
}

type readSeekCloser struct {
	*bytes.Reader
}

func (r *readSeekCloser) Close() error {
	return nil
}

func TestReaderAtReadAt(t *testing.T) {
	t.Run("seek supported", func(t *testing.T) {
		reader := bytes.NewReader([]byte("abcdef"))
		ra := &readerAt{Reader: reader, Closer: io.NopCloser(bytes.NewReader(nil)), size: 6}
		buf := make([]byte, 3)
		n, err := ra.ReadAt(buf, 2)
		require.NoError(t, err)
		require.Equal(t, 3, n)
		require.Equal(t, "cde", string(buf))
		require.Equal(t, int64(5), ra.offset)
	})

	t.Run("reader does not support seek", func(t *testing.T) {
		ro := &readOnlyBuffer{}
		ro.buf.WriteString("abcdef")
		ra := &readerAt{Reader: ro, Closer: io.NopCloser(bytes.NewReader(nil)), size: 6}
		_, err := ra.ReadAt(make([]byte, 2), 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "reader does not support seeking")
	})
}

func TestMaybeWithHTTP(t *testing.T) {
	remote, err := New("localhost:5000/library/busybox:latest", func(bool) remotes.Resolver {
		return &MockResolver{}
	})
	require.NoError(t, err)

	remote.MaybeWithHTTP(errors.New("Head https://registry/localhost:5000/v2/test/manifests/latest failed"))
	assert.True(t, remote.IsWithHTTP())

	remote = &Remote{Ref: "not a ref"}
	remote.MaybeWithHTTP(errors.New("unrelated error"))
	assert.False(t, remote.IsWithHTTP())
}

func TestResolvePullAndReaderAt(t *testing.T) {
	desc := ocispec.Descriptor{Digest: digest.FromString("manifest"), Size: 6}
	remote, err := New("docker.io/library/busybox:latest", func(withHTTP bool) remotes.Resolver {
		assert.False(t, withHTTP)
		return &MockResolver{
			ResolveFunc: func(_ context.Context, ref string) (string, ocispec.Descriptor, error) {
				require.Equal(t, "docker.io/library/busybox:latest", ref)
				return ref, desc, nil
			},
			FetcherFunc: func(_ context.Context, ref string) (remotes.Fetcher, error) {
				require.Equal(t, "docker.io/library/busybox:latest", ref)
				return remotes.FetcherFunc(func(_ context.Context, got ocispec.Descriptor) (io.ReadCloser, error) {
					require.Equal(t, desc.Digest, got.Digest)
					return &readSeekCloser{Reader: bytes.NewReader([]byte("abcdef"))}, nil
				}), nil
			},
		}
	})
	require.NoError(t, err)

	resolved, err := remote.Resolve(context.Background())
	require.NoError(t, err)
	require.Equal(t, desc.Digest, resolved.Digest)

	rc, err := remote.Pull(context.Background(), desc, false)
	require.NoError(t, err)
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, "abcdef", string(data))
	require.NoError(t, rc.Close())

	ra, err := remote.ReaderAt(context.Background(), desc, false)
	require.NoError(t, err)
	buf := make([]byte, 2)
	n, err := ra.ReadAt(buf, 1)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, "bc", string(buf))
	require.Equal(t, int64(6), ra.Size())
}
