package remote

import (
	"bytes"
	"context"
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
