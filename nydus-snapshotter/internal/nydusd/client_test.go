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
	"syscall"
	"testing"

	"github.com/containerd/errdefs"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestClient_UpdateAuth(t *testing.T) {
	tests := []struct {
		name    string
		auth    string
		handler http.HandlerFunc
		expect  func(t *testing.T, err error)
	}{
		{
			name: "update auth",
			auth: "dXNlcjpwYXNz",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Username string `json:"username"`
					Password string `json:"password"`
				}
				if r.Method != http.MethodPut || r.URL.Path != endpointBackendAuthBasic || json.NewDecoder(r.Body).Decode(&body) != nil || body.Username != "user" || body.Password != "pass" {
					w.WriteHeader(http.StatusTeapot)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "daemon without the route",
			auth: "dXNlcjpwYXNz",
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
			auth: "dXNlcjpwYXNz",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"username and password are not basic credentials"}`))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.ErrorContains(err, "username and password are not basic credentials")
			},
		},
		{
			name: "peer uid mismatch",
			auth: "dXNlcjpwYXNz",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrPermissionDenied)
			},
		},
		{
			name: "auth that is not base64",
			auth: "user:pass",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.ErrorContains(err, "decode auth")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := serve(t, tc.handler)
			tc.expect(t, NewClient(socket).UpdateAuth(t.Context(), tc.auth))
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
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "daemon failing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "503")
			},
		},
		{
			name: "daemon not listening",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Error(err)
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

func TestClient_Info(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		expect  func(t *testing.T, info *Info, err error)
	}{
		{
			name: "describe the daemon",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != endpointDaemon {
					w.WriteHeader(http.StatusTeapot)
					return
				}

				_, _ = w.Write([]byte(`{"version":"3.0.0","git_commit":"1a2b3c4d5","pid":42,"capabilities":["backend_auth_basic"]}`))
			},
			expect: func(t *testing.T, info *Info, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Info{Version: "3.0.0", GitCommit: "1a2b3c4d5", PID: 42, Capabilities: []string{CapabilityBackendAuthBasic}}, info)
			},
		},
		{
			name: "ignore fields and capabilities added later",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"3.1.0","pid":42,"capabilities":["backend_auth_basic","later"],"later":{"key":"value"}}`))
			},
			expect: func(t *testing.T, info *Info, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("3.1.0", info.Version)
				assert.Equal([]string{CapabilityBackendAuthBasic, "later"}, info.Capabilities)
			},
		},
		{
			name: "daemon of another api version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("not found\n"))
			},
			expect: func(t *testing.T, info *Info, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.Nil(info)
			},
		},
		{
			name: "description that does not parse",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":3}`))
			},
			expect: func(t *testing.T, info *Info, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "GET /api/v1/daemon: read answer")
				assert.Nil(info)
			},
		},
		{
			name: "daemon that does not listen",
			expect: func(t *testing.T, info *Info, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.ENOENT)
				assert.Nil(info)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "missing.sock")
			if tc.handler != nil {
				socket = serve(t, tc.handler)
			}

			info, err := NewClient(socket).Info(t.Context())
			tc.expect(t, info, err)
		})
	}
}

func TestClient_Metrics(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		expect  func(t *testing.T, families map[string]*dto.MetricFamily, err error)
	}{
		{
			name: "parse the metric families",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("# HELP nydus_backend_read_total Backend reads.\n# TYPE nydus_backend_read_total counter\nnydus_backend_read_total 3\n"))
			},
			expect: func(t *testing.T, families map[string]*dto.MetricFamily, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(families, 1)
				family := families["nydus_backend_read_total"]
				assert.Equal(dto.MetricType_COUNTER, family.GetType())
				assert.Equal(float64(3), family.GetMetric()[0].GetCounter().GetValue())
			},
		},
		{
			name: "metrics that do not parse",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("nydus_backend_read_total three\n"))
			},
			expect: func(t *testing.T, families map[string]*dto.MetricFamily, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "GET /metrics: read answer")
				assert.Nil(families)
			},
		},
		{
			name: "daemon answering an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expect: func(t *testing.T, families map[string]*dto.MetricFamily, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "500")
				assert.Nil(families)
			},
		},
		{
			name: "daemon that does not listen",
			expect: func(t *testing.T, families map[string]*dto.MetricFamily, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.ENOENT)
				assert.Nil(families)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "missing.sock")
			if tc.handler != nil {
				socket = serve(t, tc.handler)
			}

			families, err := NewClient(socket).Metrics(t.Context())
			tc.expect(t, families, err)
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
