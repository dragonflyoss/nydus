/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package metrics

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

var mockDaemonFamily = &dto.MetricFamily{
	Name: proto.String("nydus_backend_read_total"),
	Help: proto.String("Backend reads."),
	Type: dto.MetricType_COUNTER.Enum(),
	Metric: []*dto.Metric{
		{
			Label:   []*dto.LabelPair{{Name: proto.String("chain_id"), Value: proto.String("sha256:ab")}},
			Counter: &dto.Counter{Value: proto.Float64(3)},
		},
	},
}

func TestServer_Serve(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		daemons prometheus.GathererFunc
		expect  func(t *testing.T, code int, body string)
	}{
		{
			name:   "daemon metrics beside the snapshotter's own",
			method: http.MethodGet,
			path:   "/metrics",
			daemons: func() ([]*dto.MetricFamily, error) {
				return []*dto.MetricFamily{mockDaemonFamily}, nil
			},
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusOK, code)
				assert.Contains(body, `nydus_backend_read_total{chain_id="sha256:ab"} 3`)
				assert.Contains(body, "nydus_snapshotter_running_daemons")
			},
		},
		{
			name:   "snapshotter metrics when the daemons fail to gather",
			method: http.MethodGet,
			path:   "/metrics",
			daemons: func() ([]*dto.MetricFamily, error) {
				return nil, errors.New("foo")
			},
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusOK, code)
				assert.Contains(body, "nydus_snapshotter_running_daemons")
			},
		},
		{
			name:   "metrics",
			method: http.MethodGet,
			path:   "/metrics",
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusOK, code)
				assert.Contains(body, "nydus_snapshotter_running_daemons")
			},
		},
		{
			name:   "method not allowed",
			method: http.MethodPost,
			path:   "/metrics",
			expect: func(t *testing.T, code int, body string) {
				assert := assert.New(t)
				assert.Equal(http.StatusMethodNotAllowed, code)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			daemons := tc.daemons
			if daemons == nil {
				daemons = func() ([]*dto.MetricFamily, error) { return nil, nil }
			}

			s, err := NewServer("127.0.0.1:0", daemons)
			assert.NoError(t, err)
			served := make(chan error, 1)
			go func() { served <- s.Serve() }()

			req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://"+s.listener.Addr().String()+tc.path, strings.NewReader(""))
			assert.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			if !assert.NoError(t, err) {
				return
			}

			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assert.NoError(t, resp.Body.Close())
			tc.expect(t, resp.StatusCode, string(body))

			s.Stop()
			assert.NoError(t, <-served)
		})
	}
}

func TestNewServer(t *testing.T) {
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
				assert := assert.New(t)
				assert.ErrorContains(err, "listen metrics 127.0.0.1:-1")
			},
		},
		{
			name: "serve on a listener that is closed",
			addr: "127.0.0.1:0",
			expect: func(t *testing.T, s *Server, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(s.listener.Close())
				assert.ErrorIs(s.Serve(), net.ErrClosed)
				s.Stop()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer(tc.addr, prometheus.NewRegistry())
			tc.expect(t, s, err)
		})
	}
}
