/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

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
