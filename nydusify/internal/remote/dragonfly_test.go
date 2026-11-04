/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	schedulerv2 "d7y.io/api/v2/pkg/apis/scheduler/v2"
	request "d7y.io/dragonfly-sdk/client-request/go"
	"google.golang.org/grpc"
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

// fakeScheduler answers the seed peer listing of the SDK with no seed peers.
type fakeScheduler struct {
	schedulerv2.UnimplementedSchedulerServer
}

func (fakeScheduler) ListHosts(context.Context, *schedulerv2.ListHostsRequest) (*schedulerv2.ListHostsResponse, error) {
	return &schedulerv2.ListHostsResponse{}, nil
}

func TestEnableDragonfly(t *testing.T) {
	stop, err := EnableDragonfly(context.Background(), "")
	if err != nil || DragonflyEndpoint() != "" {
		t.Fatalf("empty endpoint must disable Dragonfly: %v %q", err, DragonflyEndpoint())
	}
	stop()

	if _, err := EnableDragonfly(context.Background(), "not a url"); err == nil {
		t.Fatal("an invalid endpoint must fail")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	schedulerv2.RegisterSchedulerServer(srv, fakeScheduler{})
	go func() { _ = srv.Serve(listener) }()
	defer srv.Stop()

	endpoint := "http://" + listener.Addr().String()
	stop, err = EnableDragonfly(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if DragonflyEndpoint() != endpoint {
		t.Fatalf("endpoint = %q, want %q", DragonflyEndpoint(), endpoint)
	}
	if _, ok := newRegistryClient(false).Transport.(*dragonflyTransport); !ok {
		t.Fatal("the registry client must route through Dragonfly once enabled")
	}
	stop()

	if DragonflyEndpoint() != "" {
		t.Fatal("stop must disable Dragonfly")
	}
	if _, ok := newRegistryClient(false).Transport.(*dragonflyTransport); ok {
		t.Fatal("the registry client must go straight to the origin once disabled")
	}
}

func TestDragonflyTransportSettlesDefinitiveStatuses(t *testing.T) {
	var originHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	challenge := http.Header{"Www-Authenticate": {`Bearer realm="https://auth.example/token"`}}
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantOrigin bool
	}{
		{"401 from the proxy", &request.ProxyError{StatusCode: 401, Header: challenge, Message: "denied"}, 401, false},
		{"404 from the backend", &request.BackendError{StatusCode: 404, Message: "no such blob"}, 404, false},
		{"422 from dfdaemon", &request.DfdaemonError{StatusCode: 422, Message: "no length"}, 422, false},
		{"wrapped 403", fmt.Errorf("get: %w", &request.ProxyError{StatusCode: 403}), 403, false},
		{"503 falls back", &request.BackendError{StatusCode: 503}, 200, true},
		{"429 falls back", &request.ProxyError{StatusCode: 429}, 200, true},
		{"408 falls back", &request.DfdaemonError{StatusCode: 408}, 200, true},
		{"507 falls back", &request.DfdaemonError{StatusCode: 507}, 200, true},
		{"timeout falls back", request.ErrRequestTimeout, 200, true},
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, tt := range tests {
			t.Run(method+" "+tt.name, func(t *testing.T) {
				originHits = 0
				client := &http.Client{Transport: &dragonflyTransport{base: http.DefaultTransport, getter: &fakeGetter{err: tt.err}}}
				req, err := http.NewRequest(method, origin.URL+"/v2/library/busybox/manifests/sha256:abc", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != tt.wantStatus || (originHits > 0) != tt.wantOrigin {
					t.Fatalf("status=%d originHits=%d, want %d / origin=%v", resp.StatusCode, originHits, tt.wantStatus, tt.wantOrigin)
				}
				if tt.wantStatus == 401 && resp.Header.Get("Www-Authenticate") == "" {
					t.Fatal("the auth challenge header must be relayed")
				}
			})
		}
	}
}
