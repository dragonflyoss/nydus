/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusd

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
)

func TestClient_UpdateAuth(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		expect  func(t *testing.T, err error)
	}{
		{
			name: "update auth",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Auth string `json:"auth"`
				}
				if r.Method != http.MethodPut || r.URL.Path != endpointBackendAuth || json.NewDecoder(r.Body).Decode(&body) != nil || body.Auth != "dXNlcjpwYXNz" {
					w.WriteHeader(http.StatusTeapot)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "daemon without the route",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("not found\n"))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.ErrorContains(err, "not found")
			},
		},
		{
			name: "invalid credential",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"auth is not base64"}`))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.ErrorContains(err, "auth is not base64")
			},
		},
		{
			name: "peer uid mismatch",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			expect: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, errdefs.ErrPermissionDenied)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := serve(t, tc.handler)
			tc.expect(t, NewClient(socket).UpdateAuth(t.Context(), "dXNlcjpwYXNz"))
		})
	}
}

func TestClient_Ready(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		expect  func(t *testing.T, err error)
	}{
		{
			name: "daemon ready",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("# metrics\n"))
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "daemon failing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			expect: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "503")
			},
		},
		{
			name: "daemon not listening",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "missing.sock")
			if tc.handler != nil {
				socket = serve(t, tc.handler)
			}

			tc.expect(t, NewClient(socket).Ready(t.Context()))
		})
	}
}

func serve(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	assert.NoError(t, err)
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket
}
