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
		root   string
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
			name: "localhost without a port",
			host: "localhost",
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://localhost", SkipVerify: true}, endpoint)
			},
		},
		{
			name: "localhost on the tls port",
			host: "127.0.0.1:443",
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://127.0.0.1:443", SkipVerify: true}, endpoint)
			},
		},
		{
			name: "localhost on the plain http port",
			host: "localhost:80",
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "http://localhost:80"}, endpoint)
			},
		},
		{
			name: "single ca",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `ca = "/etc/pki/ca.pem"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"/etc/pki/ca.pem"}, endpoint.CACerts)
			},
		},
		{
			name: "ca list holding a number",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `ca = ["ca.crt", 1]`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode ca: unexpected int64 in list")
			},
		},
		{
			name: "ca that is no path",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `ca = true`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode ca: unexpected type bool")
			},
		},
		{
			name: "hosts.toml that does not decode",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `server = `,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "hosts.toml: decode")
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
			name: "default dir without server applies tls",
			host: "registry.example.com",
			files: map[string]string{
				"_default/hosts.toml": `skip_verify = true`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry.example.com", SkipVerify: true}, endpoint)
			},
		},
		{
			name: "default dir with server is skipped with its tls",
			host: "registry.example.com",
			files: map[string]string{
				"_default/hosts.toml": `
server = "https://proxy.example.com"
ca = "proxy-ca.crt"
skip_verify = true
`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry.example.com"}, endpoint)
			},
		},
		{
			name: "docker hub server of containerd's docs is the registry",
			host: "docker.io",
			files: map[string]string{
				"docker.io/hosts.toml": `
server = "https://docker.io"

[host."https://registry-1.docker.io"]
  capabilities = ["pull", "resolve"]
`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry-1.docker.io"}, endpoint)
			},
		},
		{
			name: "server host starting with http",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `server = "httpd.example.com/v2"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://httpd.example.com", endpoint.Addr)
			},
		},
		{
			name: "server userinfo and query dropped",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `server = "https://user:password@mirror.example.com/v2?ns=docker.io"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://mirror.example.com", endpoint.Addr)
			},
		},
		{
			name: "server without a host rejected",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `server = "https://"`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "empty hosts.toml falls back to docker certs",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": "",
				"registry.example.com/ca.crt":     "",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{filepath.Join(root, "registry.example.com", "ca.crt")}, endpoint.CACerts)
			},
		},
		{
			name: "docker certs skip directories and keys",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/old.crt/keep": "",
				"registry.example.com/client.key":   "",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(endpoint.CACerts)
			},
		},
		{
			name: "no config path",
			host: "registry.example.com",
			root: "none",
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry.example.com"}, endpoint)
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
			name: "server without a scheme",
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
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "client certificate rejected",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": `client = [["client.cert", "client.key"]]`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "docker client certificate rejected",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/client.cert": "",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "default dir with server is skipped with its client certificate",
			host: "registry.example.com",
			files: map[string]string{
				"_default/hosts.toml": "server = \"https://proxy.example.com\"\nclient = [[\"client.cert\", \"client.key\"]]\n",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Endpoint{Addr: "https://registry.example.com"}, endpoint)
			},
		},
		{
			name: "default dir client certificate without a server rejected",
			host: "registry.example.com",
			files: map[string]string{
				"_default/hosts.toml": `client = [["client.cert", "client.key"]]`,
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "rejected server keeps its userinfo out of the error",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": "server = \"https://user:secret@registry.example.com/api\"\noverride_path = true\n",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.NotContains(err.Error(), "secret")
				assert.Contains(err.Error(), "registry.example.com/api")
			},
		},
		{
			name: "server that cannot be parsed keeps its userinfo out of the error",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": "server = \"https://user:secret@registry.example.com/%zz\"\n",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse server")
				assert.NotContains(err.Error(), "secret")
			},
		},
		{
			name: "server without a host keeps its userinfo out of the error",
			host: "registry.example.com",
			files: map[string]string{
				"registry.example.com/hosts.toml": "server = \"https://user:secret@/v2\"\n",
			},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.NotContains(err.Error(), "secret")
			},
		},
		{
			name:  "config path that is a file",
			host:  "registry.example.com",
			root:  "file",
			files: map[string]string{"file": ""},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "find host dir of registry.example.com")
				assert.Nil(endpoint)
			},
		},
		{
			name:  "host directory that is a file",
			host:  "registry.example.com",
			files: map[string]string{"registry.example.com": ""},
			expect: func(t *testing.T, root string, endpoint *Endpoint, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read "+filepath.Join(root, "registry.example.com", HostsFile))
				assert.Nil(endpoint)
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

			configPath := root
			switch tc.root {
			case "none":
				configPath = ""
			case "":
			default:
				configPath = filepath.Join(root, tc.root)
			}

			endpoint, err := NewHosts(configPath).Resolve(tc.host)
			tc.expect(t, root, endpoint, err)
		})
	}
}
