package remote

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
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
