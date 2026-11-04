package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRangeEnd(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		size   int64
		expect func(t *testing.T, end int64, err error)
	}{
		{
			name: "invalid blob size",
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid blob size")
			},
		},
		{
			name: "whole blob",
			size: 8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(int64(7), end)
			},
		},
		{
			name:  "open ended range",
			value: "bytes=2-",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "reversed range",
			value: "bytes=2-1",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "range past blob end",
			value: "bytes=8-9",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "signed start",
			value: "bytes=+2-4",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "multiple ranges",
			value: "bytes=0-1,4-5",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "empty suffix",
			value: "bytes=-0",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "invalid suffix",
			value: "bytes=-x",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "overflowing end",
			value: "bytes=0-9223372036854775808",
			size:  8,
			expect: func(t *testing.T, end int64, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			end, err := rangeEnd(tc.value, tc.size)

			tc.expect(t, end, err)
		})
	}
}

func TestBoundedRangeTransport_RoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), blobRangeKey{}, blobRange{end: 3, size: 8})
	canceled, cancel := context.WithCancel(ctx)
	cancel()

	tests := []struct {
		name   string
		ctx    context.Context
		header string
		expect func(t *testing.T, resp *http.Response, err error)
	}{
		{
			name:   "invalid offset",
			ctx:    ctx,
			header: "bytes=x-",
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid compact fetch offset")
				assert.Nil(resp)
			},
		},
		{
			name:   "offset past range end",
			ctx:    ctx,
			header: "bytes=5-",
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid compact fetch offset")
				assert.Nil(resp)
			},
		},
		{
			name: "canceled request",
			ctx:  canceled,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Nil(resp)
			},
		},
		{
			name: "request without compact range",
			ctx:  context.Background(),
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(http.StatusNoContent, resp.StatusCode)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(tc.ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.header != "" {
				req.Header.Set("Range", tc.header)
			}

			resp, err := boundedRangeTransport{RoundTripper: http.DefaultTransport}.RoundTrip(req)

			tc.expect(t, resp, err)
			if resp != nil {
				assert.NoError(t, resp.Body.Close())
			}
		})
	}
}
