/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
