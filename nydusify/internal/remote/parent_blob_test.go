package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type parentBlobTestResolver struct {
	remotes.Resolver
	pusher  remotes.Pusher
	fetcher remotes.Fetcher
}

func (r parentBlobTestResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return r.pusher, nil
}

func (r parentBlobTestResolver) Fetcher(context.Context, string) (remotes.Fetcher, error) {
	return r.fetcher, nil
}

type parentBlobTestPusher struct {
	*contentTestPusher
	descriptors []ocispec.Descriptor
}

func (p *parentBlobTestPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	p.descriptors = append(p.descriptors, desc)
	return p.contentTestPusher.Push(ctx, desc)
}

type parentBlobTestFetcher struct {
	data  []byte
	calls int
}

func (f *parentBlobTestFetcher) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	f.calls++
	return io.NopCloser(bytes.NewReader(f.data)), nil
}

func TestEnsureParentBlobMountedWithoutDownload(t *testing.T) {
	data := []byte("parent blob")
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(data), Size: int64(len(data))}
	pusher := &parentBlobTestPusher{contentTestPusher: &contentTestPusher{pushErr: errdefs.ErrAlreadyExists}}
	resolver := parentBlobTestResolver{pusher: pusher}

	err := ensureParentBlob(context.Background(), nil, resolver, desc,
		"registry.test:5000/ns/parent:v1", "registry.test:5000/ns/child:v2")
	require.NoError(t, err)
	require.Len(t, pusher.descriptors, 1)
	require.Equal(t, "ns/parent", pusher.descriptors[0].Annotations["containerd.io/distribution.source.registry.test"])
	require.Nil(t, desc.Annotations)
	require.Empty(t, pusher.writers)
}

func TestEnsureParentBlobFallsBackToUpload(t *testing.T) {
	data := []byte("parent blob not mounted")
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(data), Size: int64(len(data))}
	store, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	pusher := &parentBlobTestPusher{contentTestPusher: &contentTestPusher{}}
	fetcher := &parentBlobTestFetcher{data: data}
	resolver := parentBlobTestResolver{pusher: pusher, fetcher: fetcher}

	err = ensureParentBlob(context.Background(), store, resolver, desc,
		"registry.test/ns/parent:v1", "registry.test/ns/child:v2")
	require.NoError(t, err)
	require.Equal(t, 1, fetcher.calls)
	require.Len(t, pusher.writers, 1)
	require.Equal(t, data, pusher.writers[0].Bytes())
	require.Equal(t, 1, pusher.writers[0].commits)
	require.Equal(t, 1, pusher.writers[0].closes)
}

func TestEnsureParentBlobSameRepository(t *testing.T) {
	resolver := parentBlobTestResolver{}
	err := ensureParentBlob(context.Background(), nil, resolver, ocispec.Descriptor{},
		"registry.test/ns/image:v1", "registry.test/ns/image:v2")
	require.NoError(t, err)
}

func TestEnsureParentBlobRejectsDifferentRegistries(t *testing.T) {
	err := ensureParentBlob(context.Background(), nil, parentBlobTestResolver{}, ocispec.Descriptor{},
		"source.test/ns/parent:v1", "target.test/ns/child:v2")
	require.ErrorContains(t, err, "same registry")
}

func TestEnsureParentBlobsUsesMountWithoutDownloading(t *testing.T) {
	descs := []ocispec.Descriptor{
		{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromString("first"), Size: 5},
		{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromString("second"), Size: 6},
	}
	requests := make(map[digest.Digest][]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		for _, desc := range descs {
			suffix := desc.Digest.String()
			if r.URL.Path == "/v2/ns/child/blobs/"+suffix {
				requests[desc.Digest] = append(requests[desc.Digest], r.Method)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Path == "/v2/ns/child/blobs/uploads/" && r.URL.Query().Get("mount") == suffix && r.URL.Query().Get("from") == "ns/parent" {
				requests[desc.Digest] = append(requests[desc.Digest], r.Method)
				w.WriteHeader(http.StatusCreated)
				return
			}
		}
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.String(), http.StatusBadRequest)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
	require.NoError(t, err)
	err = provider.EnsureParentBlobs(context.Background(), descs, host+"/ns/parent:v1", host+"/ns/child:v2")
	require.NoError(t, err)
	for _, desc := range descs {
		require.Equal(t, []string{http.MethodHead, http.MethodPost}, requests[desc.Digest])
	}
}

var _ remotes.Fetcher = (*parentBlobTestFetcher)(nil)
var _ remotes.Pusher = (*parentBlobTestPusher)(nil)

func TestEnsureParentBlob(t *testing.T) {
	mockParentData := []byte("parent blob")
	mockParentDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(mockParentData), Size: int64(len(mockParentData))}
	mockParentErr := errors.New("registry refused")
	tests := []struct {
		name     string
		parent   string
		target   string
		pusher   *contentTestPusher
		resolver func(pusher *contentTestPusher) remotes.Resolver
		openErr  error
		expect   func(t *testing.T, pusher *contentTestPusher, err error)
	}{
		{
			name:   "invalid parent reference",
			parent: "Parent/Image:v1",
			pusher: &contentTestPusher{},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return contentTestResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse parent image "Parent/Image:v1"`)
				assert.Zero(pusher.calls)
			},
		},
		{
			name:   "invalid target reference",
			target: "Child/Image:v1",
			pusher: &contentTestPusher{},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return contentTestResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse target image "Child/Image:v1"`)
				assert.Zero(pusher.calls)
			},
		},
		{
			name:   "pusher unavailable",
			pusher: &contentTestPusher{},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return contentTestResolver{pusherErr: mockParentErr}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockParentErr)
				assert.ErrorContains(err, "create pusher for")
			},
		},
		{
			name:   "mount request fails",
			pusher: &contentTestPusher{pushErr: mockParentErr},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return contentTestResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockParentErr)
				assert.ErrorContains(err, "mount parent blob "+mockParentDesc.Digest.String())
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name:   "parent fetcher unavailable",
			pusher: &contentTestPusher{},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return contentTestResolver{pusher: pusher, fetcherErr: mockParentErr}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockParentErr)
				assert.ErrorContains(err, "get fetcher for parent")
				assert.Equal(1, pusher.writers[0].closes)
			},
		},
		{
			name:   "parent download fails",
			pusher: &contentTestPusher{},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return contentTestResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.ErrorContains(err, "download parent blob")
				assert.Empty(pusher.writers[0].Bytes())
				assert.Equal(1, pusher.writers[0].closes)
			},
		},
		{
			name:   "downloaded parent cannot be opened",
			pusher: &contentTestPusher{},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return parentBlobTestResolver{pusher: pusher, fetcher: &parentBlobTestFetcher{data: mockParentData}}
			},
			openErr: mockParentErr,
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockParentErr)
				assert.ErrorContains(err, "open downloaded parent blob")
				assert.Equal(1, pusher.writers[0].closes)
			},
		},
		{
			name:   "upload fails",
			pusher: &contentTestPusher{writeErr: mockParentErr},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return parentBlobTestResolver{pusher: pusher, fetcher: &parentBlobTestFetcher{data: mockParentData}}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockParentErr)
				assert.ErrorContains(err, "upload parent blob")
				assert.Zero(pusher.writers[0].commits)
				assert.Equal(1, pusher.writers[0].closes)
			},
		},
		{
			name:   "blob published during upload",
			pusher: &contentTestPusher{writeErr: errdefs.ErrAlreadyExists},
			resolver: func(pusher *contentTestPusher) remotes.Resolver {
				return parentBlobTestResolver{pusher: pusher, fetcher: &parentBlobTestFetcher{data: mockParentData}}
			},
			expect: func(t *testing.T, pusher *contentTestPusher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Zero(pusher.writers[0].commits)
				assert.Equal(1, pusher.writers[0].closes)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent, target := "registry.test/ns/parent:v1", "registry.test/ns/child:v1"
			if tc.parent != "" {
				parent = tc.parent
			}
			if tc.target != "" {
				target = tc.target
			}
			base, err := local.NewStore(t.TempDir())
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			store := &contentTestStore{Store: base, data: mockParentData, openErr: tc.openErr}
			err = ensureParentBlob(context.Background(), store, tc.resolver(tc.pusher), mockParentDesc, parent, target)
			tc.expect(t, tc.pusher, err)
		})
	}
}
