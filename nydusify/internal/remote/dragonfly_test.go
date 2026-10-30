/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	request "d7y.io/dragonfly-sdk/client-request/go"
)

type fakeGetter struct {
	calls  int
	err    error
	header http.Header
	closed bool
}

type closeRecorder struct {
	io.Reader
	closed *bool
}

func (c closeRecorder) Close() error { *c.closed = true; return nil }

func (g *fakeGetter) Get(_ context.Context, _ *request.GetRequest) (*request.GetResponse, error) {
	g.calls++
	if g.err != nil {
		return nil, g.err
	}
	return &request.GetResponse{
		Success:    true,
		StatusCode: http.StatusOK,
		Header:     g.header,
		Body:       closeRecorder{strings.NewReader("from-dragonfly"), &g.closed},
	}, nil
}

func TestDragonflyTransport(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("from-origin"))
	}))
	defer origin.Close()

	tests := []struct {
		name      string
		method    string
		path      string
		err       error
		want      string
		wantCalls int
	}{
		{"manifest GET", http.MethodGet, "/v2/library/busybox/manifests/sha256:abc", nil, "from-dragonfly", 1},
		{"blob GET", http.MethodGet, "/v2/library/busybox/blobs/sha256:abc", nil, "from-dragonfly", 1},
		{"HEAD bypasses", http.MethodHead, "/v2/library/busybox/manifests/latest", nil, "", 0},
		{"token endpoint bypasses", http.MethodGet, "/token", nil, "from-origin", 0},
		{"failure falls back", http.MethodGet, "/v2/library/busybox/blobs/sha256:abc", errors.New("boom"), "from-origin", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &fakeGetter{err: tt.err}
			client := &http.Client{Transport: &dragonflyTransport{base: http.DefaultTransport, getter: g}}
			req, err := http.NewRequest(tt.method, origin.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != tt.want || g.calls != tt.wantCalls {
				t.Fatalf("body=%q calls=%d, want %q / %d", body, g.calls, tt.want, tt.wantCalls)
			}
		})
	}
}

func TestDragonflyTransportHeadByDigest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:origin")
	}))
	defer origin.Close()

	const path = "/v2/library/busybox/manifests/sha256:abc"
	full := http.Header{"Content-Length": {"14"}, "Content-Type": {"application/vnd.oci.image.manifest.v1+json"}}
	tests := []struct {
		name       string
		path       string
		header     http.Header
		err        error
		wantCalls  int
		wantDigest string
		wantSize   int64
	}{
		{"served by dragonfly", path, full, nil, 1, "sha256:abc", 14},
		{"no content type falls back", path, http.Header{"Content-Length": {"14"}}, nil, 1, "sha256:origin", -1},
		{"no length falls back", path, http.Header{"Content-Type": {"x"}}, nil, 1, "sha256:origin", -1},
		{"failure falls back", path, full, errors.New("boom"), 1, "sha256:origin", -1},
		{"tag goes to origin", "/v2/library/busybox/manifests/latest", full, nil, 0, "sha256:origin", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &fakeGetter{err: tt.err, header: tt.header}
			client := &http.Client{Transport: &dragonflyTransport{base: http.DefaultTransport, getter: g}}
			req, err := http.NewRequest(http.MethodHead, origin.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if g.calls != tt.wantCalls || resp.Header.Get("Docker-Content-Digest") != tt.wantDigest || resp.ContentLength != tt.wantSize {
				t.Fatalf("calls=%d digest=%q size=%d, want %d / %q / %d",
					g.calls, resp.Header.Get("Docker-Content-Digest"), resp.ContentLength, tt.wantCalls, tt.wantDigest, tt.wantSize)
			}
			if tt.wantCalls == 1 && tt.err == nil && !g.closed {
				t.Fatal("the unread body must be closed")
			}
		})
	}
}
