package remote

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type compactFetchFunc func(context.Context, ocispec.Descriptor) (io.ReadCloser, error)

func (f compactFetchFunc) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	return f(ctx, desc)
}

type compactNonSeekReader struct {
	io.Reader
	closed bool
}

func (r *compactNonSeekReader) Close() error { r.closed = true; return nil }

func TestOpenCompactBlobRejectsInvalidInputsAndClosesUnsupportedReaders(t *testing.T) {
	p, err := NewProvider(Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	desc := ocispec.Descriptor{Digest: digest.FromString("blob"), Size: 4}
	_, err = p.OpenBlob(context.Background(), ocispec.Descriptor{}, "example.test/repo:tag", Target, "")
	require.ErrorContains(t, err, "invalid blob size")
	_, err = p.OpenBlob(context.Background(), desc, "://invalid", Target, "")
	require.Error(t, err)
	key := struct {
		side Side
		ref  string
	}{Target, "example.test/repo:tag"}
	failure := errors.New("fetch failed")
	p.blobFetchers.Store(key, compactFetchFunc(func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) { return nil, failure }))
	_, err = p.OpenBlob(context.Background(), desc, key.ref, Target, "")
	require.ErrorIs(t, err, failure)
	reader := &compactNonSeekReader{Reader: strings.NewReader("blob")}
	p.blobFetchers.Store(key, compactFetchFunc(func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) { return reader, nil }))
	_, err = p.OpenBlob(context.Background(), desc, key.ref, Target, "")
	require.ErrorContains(t, err, "does not support seeking")
	require.True(t, reader.closed)
}

func TestOpenBlobDefersTransferAndSeeks(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		requests.Add(1)
		require.Equal(t, "bytes=4-5", r.Header.Get("Range"))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "blob", time.Time{}, strings.NewReader("abcdefgh"))
	}))
	defer server.Close()
	provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
	require.NoError(t, err)
	reader, err := provider.OpenBlob(context.Background(), ocispec.Descriptor{Digest: digest.FromString("abcdefgh"), Size: 8},
		strings.TrimPrefix(server.URL, "http://")+"/test:v1", Target, "bytes=4-5")
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	require.Zero(t, requests.Load())
	_, err = reader.Seek(4, io.SeekStart)
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "ef", string(data))
	require.Equal(t, int32(1), requests.Load())
}
