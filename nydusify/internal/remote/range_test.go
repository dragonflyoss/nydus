package remote

import (
	"context"
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

func TestCompactBoundedRegistryRanges(t *testing.T) {
	for _, tc := range []struct {
		name, request, upstream string
		start                   int64
		want                    string
	}{
		{"middle", "bytes=2-4", "bytes=2-4", 2, "cde"},
		{"start", "bytes=0-1", "bytes=0-1", 0, "ab"},
		{"suffix", "bytes=-2", "bytes=6-7", 6, "gh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var transferred atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tc.upstream, r.Header.Get("Range"))
				require.Equal(t, "identity", r.Header.Get("Accept-Encoding"))
				w.Header().Set("Content-Type", "application/octet-stream")
				http.ServeContent(w, r, "blob", time.Time{}, strings.NewReader("abcdefgh"))
				transferred.Add(1)
			}))
			defer origin.Close()
			// Exercise an authenticated registry challenge and redirect to object storage.
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, pass, ok := r.BasicAuth()
				if !ok || user != "user" || pass != "pass" {
					w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, origin.URL+"/object", http.StatusTemporaryRedirect)
			}))
			defer registry.Close()
			p, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
			require.NoError(t, err)
			p.credFunc = func(string) (string, string, error) { return "user", "pass", nil }
			reader, err := p.OpenBlob(context.Background(), ocispec.Descriptor{Digest: digest.FromString("abcdefgh"), Size: 8},
				strings.TrimPrefix(registry.URL, "http://")+"/test:v1", Target, tc.request)
			require.NoError(t, err)
			defer func() { require.NoError(t, reader.Close()) }()
			_, err = reader.Seek(tc.start, io.SeekStart)
			require.NoError(t, err)
			data, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(data))
			require.Equal(t, int32(1), transferred.Load())
		})
	}
}

func TestCompactRejectsIgnoredRanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "abcdefgh")
	}))
	defer server.Close()
	p, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
	require.NoError(t, err)
	reader, err := p.OpenBlob(context.Background(), ocispec.Descriptor{Digest: digest.FromString("abcdefgh"), Size: 8},
		strings.TrimPrefix(server.URL, "http://")+"/test:v1", Target, "bytes=0-1")
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	_, err = io.ReadAll(reader)
	require.ErrorContains(t, err, "did not honor compact range")
}

func TestCompactRangeValidation(t *testing.T) {
	_, err := rangeEnd("", 0)
	require.Error(t, err)
	end, err := rangeEnd("", 8)
	require.NoError(t, err)
	require.EqualValues(t, 7, end)
	for _, value := range []string{"bytes=2-", "bytes=2-1", "bytes=8-9", "bytes=+2-4", "bytes=0-1,4-5", "bytes=-0", "bytes=-x", "bytes=0-9223372036854775808"} {
		_, err := rangeEnd(value, 8)
		require.Error(t, err, value)
	}
}

func TestCompactTransportRejectsInvalidOffsetsAndPropagatesErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	transport := boundedRangeTransport{http.DefaultTransport}
	ctx := context.WithValue(context.Background(), blobRangeKey{}, blobRange{end: 3, size: 8})
	for _, value := range []string{"bytes=x-", "bytes=5-"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Range", value)
		response, err := transport.RoundTrip(req)
		if response != nil {
			require.NoError(t, response.Body.Close())
		}
		require.ErrorContains(t, err, "invalid compact fetch offset")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	req, err := http.NewRequestWithContext(canceled, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(req)
	if response != nil {
		require.NoError(t, response.Body.Close())
	}
	require.ErrorIs(t, err, context.Canceled)
	// Ordinary requests must bypass compact-specific response validation.
	req, err = http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	response, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.NoError(t, response.Body.Close())
}
