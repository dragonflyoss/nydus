/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package metrics

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer_Serve(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		ready  error
		expect func(t *testing.T, code int, body string)
	}{
		{
			name:   "live",
			method: http.MethodGet,
			path:   "/livez",
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusOK, code)
				assert.Equal("ok\n", body)
			},
		},
		{
			name:   "live while not ready",
			method: http.MethodGet,
			path:   "/livez",
			ready:  errors.New("foo"),
			expect: func(t *testing.T, code int, body string) {
				assert.Equal(t, http.StatusOK, code)
			},
		},
		{
			name:   "ready",
			method: http.MethodGet,
			path:   "/readyz",
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusOK, code)
				assert.Equal("ok\n", body)
			},
		},
		{
			name:   "not ready",
			method: http.MethodGet,
			path:   "/readyz",
			ready:  errors.New("foo"),
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusServiceUnavailable, code)
				assert.Equal("foo\n", body)
			},
		},
		{
			name:   "metrics",
			method: http.MethodGet,
			path:   "/metrics",
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusOK, code)
				assert.Contains(body, "nydus_snapshotter_daemon_running")
			},
		},
		{
			name:   "method not allowed",
			method: http.MethodPost,
			path:   "/livez",
			expect: func(t *testing.T, code int, body string) {
				assert.Equal(t, http.StatusMethodNotAllowed, code)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer("127.0.0.1:0", func() error { return tc.ready })
			assert.NoError(t, err)
			served := make(chan error, 1)
			go func() { served <- s.Serve() }()

			req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://"+s.listener.Addr().String()+tc.path, strings.NewReader(""))
			assert.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assert.NoError(t, resp.Body.Close())
			tc.expect(t, resp.StatusCode, string(body))

			s.Stop()
			assert.NoError(t, <-served)
		})
	}
}

func TestServer_NewServer(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		expect func(t *testing.T, s *Server, err error)
	}{
		{
			name: "bind an address",
			addr: "127.0.0.1:0",
			expect: func(t *testing.T, s *Server, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(s.listener.Close())
			},
		},
		{
			name: "invalid address",
			addr: "127.0.0.1:-1",
			expect: func(t *testing.T, s *Server, err error) {
				assert.ErrorContains(t, err, "listen metrics 127.0.0.1:-1")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer(tc.addr, func() error { return nil })
			tc.expect(t, s, err)
		})
	}
}
