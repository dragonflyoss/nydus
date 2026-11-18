/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	mockDockerConfig = `{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"}}}`

	mockDockerHubTarget registryKey = "docker.io/library/ubuntu"
)

func TestNewDockerConfigProvider(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect func(t *testing.T, d *dockerConfigProvider)
	}{
		{
			name: "kubelet search paths",
			expect: func(t *testing.T, d *dockerConfigProvider) {
				assert := assert.New(t)
				assert.Equal([]string{"/var/lib/kubelet/config.json", "/root/.docker/config.json", "/.docker/config.json"}, d.paths)
			},
		},
		{
			name: "configured path",
			path: "/etc/nydus-snapshotter/config.json",
			expect: func(t *testing.T, d *dockerConfigProvider) {
				assert := assert.New(t)
				assert.Equal([]string{"/etc/nydus-snapshotter/config.json"}, d.paths)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newDockerConfigProvider(tc.path))
		})
	}
}

func TestDockerConfigProvider_lookup(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		expect func(t *testing.T, d *dockerConfigProvider, dir string)
	}{
		{
			name:  "read auths",
			files: map[string]string{"second.json": mockDockerConfig},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				creds := d.lookup(t.Context(), mockDockerHubTarget)
				assert.Len(creds, 1)
				assert.Equal(mockBasic, creds[0].basic())
				assert.Equal(filepath.Join(dir, "second.json"), creds[0].source)
			},
		},
		{
			name: "first file found wins",
			files: map[string]string{
				"first.json":  `{"auths":{"docker.io":{"username":"first","password":"pass"}}}`,
				"second.json": mockDockerConfig,
			},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				creds := d.lookup(t.Context(), mockDockerHubTarget)
				assert.Len(creds, 1)
				assert.Equal("first", creds[0].Username)
			},
		},
		{
			name:  "no file",
			files: map[string]string{},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				assert.Empty(d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name:  "malformed file",
			files: map[string]string{"first.json": `{"auths":`},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				assert.Empty(d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name: "malformed file falls back to the next",
			files: map[string]string{
				"first.json":  `{"auths":`,
				"second.json": mockDockerConfig,
			},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				creds := d.lookup(t.Context(), mockDockerHubTarget)
				assert.Len(creds, 1)
				assert.Equal(filepath.Join(dir, "second.json"), creds[0].source)
			},
		},
		{
			name:  "credential helpers only",
			files: map[string]string{"first.json": `{"credsStore":"desktop","credHelpers":{"gcr.io":"gcloud"}}`},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				assert.Empty(d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name: "keep the credentials read last while the file does not parse",
			files: map[string]string{
				"first.json":  mockDockerConfig,
				"second.json": `{"auths":{"registry.example.com":{"username":"user","password":"pass"}}}`,
			},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				assert.Len(d.lookup(t.Context(), mockDockerHubTarget), 1)
				assert.NoError(os.WriteFile(filepath.Join(dir, "first.json"), []byte(`{"auths":`), 0o600))
				creds := d.lookup(t.Context(), mockDockerHubTarget)
				assert.Len(creds, 1)
				assert.Empty(d.lookup(t.Context(), "registry.example.com/app"))
				assert.NoError(os.WriteFile(filepath.Join(dir, "first.json"), []byte(`{"auths":{}}`), 0o600))
				assert.Empty(d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name:  "read again after a change",
			files: map[string]string{"first.json": mockDockerConfig},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				assert.Len(d.lookup(t.Context(), mockDockerHubTarget), 1)
				assert.NoError(os.WriteFile(filepath.Join(dir, "first.json"), []byte(`{"auths":{"registry.example.com":{"username":"user","password":"pass"}}}`), 0o600))
				assert.Empty(d.lookup(t.Context(), mockDockerHubTarget))
				assert.Len(d.lookup(t.Context(), "registry.example.com/app"), 1)
			},
		},
		{
			name:  "skip a config that is a directory",
			files: map[string]string{"second.json": mockDockerConfig},
			expect: func(t *testing.T, d *dockerConfigProvider, dir string) {
				assert := assert.New(t)
				assert.NoError(os.Mkdir(filepath.Join(dir, "first.json"), 0o700))
				assert.Len(d.lookup(t.Context(), mockDockerHubTarget), 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tc.files {
				assert.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
			}

			d := &dockerConfigProvider{paths: []string{filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")}}
			tc.expect(t, d, dir)
		})
	}
}
