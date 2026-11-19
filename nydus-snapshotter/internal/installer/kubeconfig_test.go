/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

func TestInstaller_syncKubeconfig(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		prepare func(t *testing.T, cfg *Config)
		expect  func(t *testing.T, cfg *Config, err error)
	}{
		{
			name:    "write kubeconfig",
			host:    "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				info, err := os.Stat(hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes"))
				assert.NoError(err)
				assert.Equal(os.ModeDir|0o700, info.Mode())
				assertFile(t, hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/token"), mockToken, 0o600)
				assertFile(t, hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/ca.crt"), mockCA, 0o644)
				info, err = os.Stat(hostPath(t, cfg, config.DefaultAuthKubeconfig))
				assert.NoError(err)
				assert.Equal(os.FileMode(0o600), info.Mode())
				kubeconfig, err := clientcmd.LoadFromFile(hostPath(t, cfg, config.DefaultAuthKubeconfig))
				assert.NoError(err)
				current := kubeconfig.Contexts[kubeconfig.CurrentContext]
				assert.Equal("https://10.96.0.1:443", kubeconfig.Clusters[current.Cluster].Server)
				assert.Equal("/run/nydus-snapshotter/kubernetes/ca.crt", kubeconfig.Clusters[current.Cluster].CertificateAuthority)
				assert.Equal("/run/nydus-snapshotter/kubernetes/token", kubeconfig.AuthInfos[current.AuthInfo].TokenFile)
			},
		},
		{
			name: "rotate token",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, New(cfg, nil).syncKubeconfig(t.Context()))
				writeFiles(t, cfg.TokenDir, map[string]string{"token": "rotated"})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/token"), "rotated", 0o600)
			},
		},
		{
			name:    "ipv6 service host",
			host:    "fd00::1",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				kubeconfig, err := clientcmd.LoadFromFile(hostPath(t, cfg, config.DefaultAuthKubeconfig))
				assert.NoError(err)
				assert.Equal("https://[fd00::1]:443", kubeconfig.Clusters["default"].Server)
			},
		},
		{
			name:    "not in cluster",
			host:    "",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "skip without kube secret",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": readFile(t, "../../deploy/nydus-snapshotter/config.yaml")})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "follow the host config when the payload config is invalid",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.HostRoot, map[string]string{config.DefaultPath: mockKubeSecretConfig})
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockInvalidConfig})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/token"), mockToken, 0o600)
			},
		},
		{
			name: "invalid payload config without a host config",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockInvalidConfig})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse payload config")
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "missing token",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Remove(filepath.Join(cfg.TokenDir, "token")))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "missing ca",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Remove(filepath.Join(cfg.TokenDir, "ca.crt")))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read service account ca")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "host directory that cannot be created",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.HostRoot, map[string]string{filepath.Dir(config.DefaultAuthKubeconfig): ""})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create "+hostPath(t, cfg, filepath.Dir(config.DefaultAuthKubeconfig)))
			},
		},
		{
			name: "host path that cannot be resolved",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Symlink("run", filepath.Join(cfg.HostRoot, "run")))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path "+filepath.Dir(config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "invalid payload config and a host config that cannot be resolved",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockInvalidConfig})
				assert.NoError(t, os.Symlink("etc", filepath.Join(cfg.HostRoot, "etc")))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse payload config")
			},
		},
		{
			name: "invalid payload config and invalid host config",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockInvalidConfig})
				writeFiles(t, cfg.HostRoot, map[string]string{config.DefaultPath: mockInvalidConfig})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse payload config")
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			cfg := newConfig(t)
			writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockKubeSecretConfig})
			tc.prepare(t, cfg)

			tc.expect(t, cfg, New(cfg, nil).syncKubeconfig(t.Context()))
		})
	}
}
