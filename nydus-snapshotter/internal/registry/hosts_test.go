/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
)

func TestHosts_Resolve(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		files  map[string]string
		expect func(t *testing.T, root string, endpoint *Endpoint, err error)
	}{
		{
			name: "docker hub without config",
			host: "docker.io",
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry-1.docker.io"}, endpoint)
			},
		},
		{
			name: "localhost with port",
			host: "localhost:5000",
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "http://localhost:5000", SkipVerify: true}, endpoint)
			},
		},
		{
			name: "hosts.toml with server and ca list",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `
server = "https://registry.example.com/prefix/"
ca = ["ca.crt", "/etc/pki/extra.pem"]
skip_verify = true

[host."https://mirror.example.com"]
  capabilities = ["pull"]
`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{
					Addr:       "https://registry.example.com/prefix",
					SkipVerify: true,
					CACerts:    []string{filepath.Join(root, "registry.example.com", "ca.crt"), "/etc/pki/extra.pem"},
				}, endpoint)
			},
		},
		{
			name: "host dir with port uses containerd's name",
			host: "registry.example.com:5000",
			files: map[string]string{
				"registry.example.com_5000_/hosts.toml": `ca = "ca.crt"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{filepath.Join(root, "registry.example.com_5000_", "ca.crt")}, endpoint.CACerts)
			},
		},
		{
			name: "default dir applies tls but not server",
			host: "registry.example.com",
			files: map[string]string{
				"_default/hosts.toml": `
server = "https://proxy.example.com"
skip_verify = true
`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry.example.com", SkipVerify: true}, endpoint)
			},
		},
		{
			name: "docker certs without hosts.toml",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/ca.crt": "",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{filepath.Join(root, "registry.example.com", "ca.crt")}, endpoint.CACerts)
			},
		},
		{
			name: "server without a scheme or with the api root",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `server = "registry.example.com/prefix/v2/"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://registry.example.com/prefix", endpoint.Addr)
			},
		},
		{
			name: "server at the api root",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `server = "http://registry.example.com:5000/v2"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("http://registry.example.com:5000", endpoint.Addr)
			},
		},
		{
			name: "override path rejected",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": "server = \"https://registry.example.com/api\"\noverride_path = true\n",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert.ErrorIs(t, err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "client certificate rejected",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `client = [["client.cert", "client.key"]]`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert.ErrorIs(t, err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "docker client certificate rejected",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/client.cert": "",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert.ErrorIs(t, err, errdefs.ErrNotImplemented)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				path := filepath.Join(root, name)
				assert.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				assert.NoError(t, os.WriteFile(path, []byte(content), 0o644))
			}

			endpoint, err := NewHosts(root).Resolve(tc.host)
			tc.expect(t, root, endpoint, err)
		})
	}
}
