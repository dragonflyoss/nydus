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

	mockDockerHubTarget = "docker.io/library/ubuntu"
)

func TestDockerConfig_newDockerConfig(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect func(t *testing.T, d *dockerConfig)
	}{
		{
			name: "kubelet search paths",
			expect: func(t *testing.T, d *dockerConfig) {
				assert.Equal(t, []string{"/var/lib/kubelet/config.json", "/root/.docker/config.json", "/.docker/config.json"}, d.paths)
			},
		},
		{
			name: "configured path",
			path: "/etc/nydus-v3/config.json",
			expect: func(t *testing.T, d *dockerConfig) {
				assert.Equal(t, []string{"/etc/nydus-v3/config.json"}, d.paths)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newDockerConfig(tc.path))
		})
	}
}

func TestDockerConfig_lookup(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		expect func(t *testing.T, d *dockerConfig, dir string)
	}{
		{
			name:  "read auths",
			files: map[string]string{"second.json": mockDockerConfig},
			expect: func(t *testing.T, d *dockerConfig, dir string) {
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
			expect: func(t *testing.T, d *dockerConfig, dir string) {
				assert := assert.New(t)
				creds := d.lookup(t.Context(), mockDockerHubTarget)
				assert.Len(creds, 1)
				assert.Equal("first", creds[0].Username)
			},
		},
		{
			name:  "no file",
			files: map[string]string{},
			expect: func(t *testing.T, d *dockerConfig, dir string) {
				assert.Empty(t, d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name:  "malformed file",
			files: map[string]string{"first.json": `{"auths":`},
			expect: func(t *testing.T, d *dockerConfig, dir string) {
				assert.Empty(t, d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name: "malformed file falls back to the next",
			files: map[string]string{
				"first.json":  `{"auths":`,
				"second.json": mockDockerConfig,
			},
			expect: func(t *testing.T, d *dockerConfig, dir string) {
				assert := assert.New(t)
				creds := d.lookup(t.Context(), mockDockerHubTarget)
				assert.Len(creds, 1)
				assert.Equal(filepath.Join(dir, "second.json"), creds[0].source)
			},
		},
		{
			name:  "credential helpers only",
			files: map[string]string{"first.json": `{"credsStore":"desktop","credHelpers":{"gcr.io":"gcloud"}}`},
			expect: func(t *testing.T, d *dockerConfig, dir string) {
				assert.Empty(t, d.lookup(t.Context(), mockDockerHubTarget))
			},
		},
		{
			name:  "read again after a change",
			files: map[string]string{"first.json": mockDockerConfig},
			expect: func(t *testing.T, d *dockerConfig, dir string) {
				assert := assert.New(t)
				assert.Len(d.lookup(t.Context(), mockDockerHubTarget), 1)
				assert.NoError(os.WriteFile(filepath.Join(dir, "first.json"), []byte(`{"auths":{"registry.example.com":{"username":"user","password":"pass"}}}`), 0o600))
				assert.Empty(d.lookup(t.Context(), mockDockerHubTarget))
				assert.Len(d.lookup(t.Context(), "registry.example.com/app"), 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tc.files {
				assert.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
			}

			d := &dockerConfig{paths: []string{filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")}}
			tc.expect(t, d, dir)
		})
	}
}
