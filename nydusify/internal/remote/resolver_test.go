/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/stretchr/testify/assert"
)

var (
	mockAuth = base64.StdEncoding.EncodeToString([]byte("user:secret"))
)

func mockDockerConfig(t *testing.T, config string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	previous := dockerconfig.Dir()
	dockerconfig.SetDir(dir)
	t.Cleanup(func() { dockerconfig.SetDir(previous) })
}

// mockStallTimeout shortens the stall timeout until t completes.
func mockStallTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := stallTimeout
	stallTimeout = timeout
	t.Cleanup(func() { stallTimeout = previous })
}

func TestStallTransport_RoundTrip(t *testing.T) {
	const timeout = 100 * time.Millisecond
	mockSilence := func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

	tests := []struct {
		name        string
		method      string
		everyMethod bool
		canceled    bool
		handler     http.HandlerFunc
		expect      func(t *testing.T, resp *http.Response, err error)
	}{
		{
			name:    "headers never arrive",
			method:  http.MethodGet,
			handler: mockSilence,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.Nil(resp)
				assert.ErrorIs(err, stallError{timeout})
				assert.NotErrorIs(err, context.Canceled)
				assert.True(isTransientPushError(err))
			},
		},
		{
			name:   "body stops arriving",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("partial"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			},
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := io.ReadAll(resp.Body)
				assert.Equal("partial", string(data))
				assert.ErrorIs(err, stallError{timeout})
				assert.True(isTransientPushError(err))
			},
		},
		{
			name:   "time between reads does not count",
			method: http.MethodGet,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("complete"))
			},
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				first := make([]byte, 1)
				_, err = io.ReadFull(resp.Body, first)
				assert.NoError(err)
				time.Sleep(3 * timeout)
				rest, err := io.ReadAll(resp.Body)
				assert.NoError(err)
				assert.Equal("complete", string(first)+string(rest))
			},
		},
		{
			name:   "upload answer may take long",
			method: http.MethodPut,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(3 * timeout)
				w.WriteHeader(http.StatusCreated)
			},
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(http.StatusCreated, resp.StatusCode)
			},
		},
		{
			name:        "every method is watched",
			method:      http.MethodPost,
			everyMethod: true,
			handler:     mockSilence,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.Nil(resp)
				assert.ErrorIs(err, stallError{timeout})
			},
		},
		{
			name:     "canceled by the caller",
			method:   http.MethodGet,
			canceled: true,
			handler:  mockSilence,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.Nil(resp)
				assert.ErrorIs(err, context.Canceled)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}

			req, err := http.NewRequestWithContext(ctx, tc.method, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := stallTransport{base: http.DefaultTransport, timeout: timeout, everyMethod: tc.everyMethod}.RoundTrip(req)
			if resp != nil {
				defer func() { _ = resp.Body.Close() }()
			}

			tc.expect(t, resp, err)
		})
	}
}

func TestNewResolver(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, err error)
	}{
		{
			name: "silent token server",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, stallError{stallTimeout})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockStallTimeout(t, 100*time.Millisecond)
			tokens := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				// The server only notices the client leaving once the body is read.
				_, _ = io.Copy(io.Discard, r.Body)
				<-r.Context().Done()
			}))
			defer tokens.Close()
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+tokens.URL+`/token",service="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer registry.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			credFunc := func(string) (string, string, error) { return "user", "secret", nil }

			_, _, err := newResolver(false, true, credFunc, newRegistryClient(false)).Resolve(ctx, strings.TrimPrefix(registry.URL, "http://")+"/repo/image:v1")

			tc.expect(t, err)
		})
	}
}

func TestTransientStatusTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
		expect func(t *testing.T, resp *http.Response, err error)
	}{
		{
			name:   "transient status of a download",
			method: http.MethodGet,
			status: http.StatusServiceUnavailable,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.Nil(resp)
				var status remoteserrors.ErrUnexpectedStatus
				assert.ErrorAs(err, &status)
				assert.Equal(http.StatusServiceUnavailable, status.StatusCode)
				assert.Equal("unavailable", string(status.Body))
				assert.True(isTransientPushError(err))
			},
		},
		{
			name:   "transient status of a head",
			method: http.MethodHead,
			status: http.StatusTooManyRequests,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.Nil(resp)
				assert.True(isTransientPushError(err))
			},
		},
		{
			name:   "definitive status of a download",
			method: http.MethodGet,
			status: http.StatusNotFound,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(http.StatusNotFound, resp.StatusCode)
			},
		},
		{
			name:   "transient status of an upload",
			method: http.MethodPut,
			status: http.StatusServiceUnavailable,
			expect: func(t *testing.T, resp *http.Response, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(http.StatusServiceUnavailable, resp.StatusCode)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("unavailable"))
			}))
			defer server.Close()
			req, err := http.NewRequest(tc.method, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := transientStatusTransport{http.DefaultTransport}.RoundTrip(req)
			if resp != nil {
				defer func() { _ = resp.Body.Close() }()
			}

			tc.expect(t, resp, err)
		})
	}
}

func TestNewDockerConfigCredFunc(t *testing.T) {
	tests := []struct {
		name   string
		config string
		host   string
		expect func(t *testing.T, username, password string, err error)
	}{
		{
			name:   "registry credentials",
			config: `{"auths":{"registry.test":{"auth":"` + mockAuth + `"}}}`,
			host:   "registry.test",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("user", username)
				assert.Equal("secret", password)
			},
		},
		{
			name:   "docker hub uses legacy key",
			config: `{"auths":{"https://index.docker.io/v1/":{"auth":"` + base64.StdEncoding.EncodeToString([]byte("hub:token")) + `"}}}`,
			host:   "registry-1.docker.io",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("hub", username)
				assert.Equal("token", password)
			},
		},
		{
			name:   "unknown registry is anonymous",
			config: `{"auths":{}}`,
			host:   "registry.test",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(username)
				assert.Empty(password)
			},
		},
		{
			name:   "credential helper failure",
			config: `{"credsStore":"nydusify-missing-helper"}`,
			host:   "registry.test",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `get auth config for "registry.test"`)
				assert.Empty(username)
				assert.Empty(password)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockDockerConfig(t, tc.config)
			username, password, err := NewDockerConfigCredFunc()(tc.host)

			tc.expect(t, username, password, err)
		})
	}
}
