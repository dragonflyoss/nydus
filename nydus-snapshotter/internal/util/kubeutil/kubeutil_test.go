/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubeutil

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
)

func TestAPIServer(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		port   string
		expect func(t *testing.T, server string, err error)
	}{
		{
			name: "ipv4 host",
			host: "10.96.0.1",
			port: "443",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://10.96.0.1:443", server)
			},
		},
		{
			name: "ipv6 host",
			host: "fd00::1",
			port: "443",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://[fd00::1]:443", server)
			},
		},
		{
			name: "pod without a host",
			port: "443",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(server)
			},
		},
		{
			name: "pod without a port",
			host: "10.96.0.1",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(server)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", tc.port)
			server, err := APIServer()
			tc.expect(t, server, err)
		})
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		dir    string
		expect func(t *testing.T, client kubernetes.Interface, err error)
	}{
		{
			name: "client of the pod's api server",
			host: "10.96.0.1",
			dir:  filepath.Join("testdata", "serviceaccount"),
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotNil(client)
			},
		},
		{
			name: "ca that is no certificate",
			host: "10.96.0.1",
			dir:  filepath.Join("testdata", "serviceaccount-invalid-ca"),
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unable to load root certificates")
			},
		},
		{
			name: "pod without an api server",
			dir:  filepath.Join("testdata", "serviceaccount"),
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Nil(client)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			client, err := NewClient(tc.dir)
			tc.expect(t, client, err)
		})
	}
}
