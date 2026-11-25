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
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

func TestInstaller_syncKubeconfig(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		prepare func(t *testing.T, cfg *config.Config)
		expect  func(t *testing.T, err error)
	}{
		{
			name:    "write kubeconfig",
			host:    "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				info, err := os.Stat(filepath.Join(hostRootMount, "run/nydus-snapshotter/kubernetes"))
				if assert.NoError(err) {
					assert.Equal(os.ModeDir|0o700, info.Mode())
				}

				for path, file := range map[string]fstest.MapFile{
					"run/nydus-snapshotter/kubernetes/token":  {Data: []byte(mockToken), Mode: 0o600},
					"run/nydus-snapshotter/kubernetes/ca.crt": {Data: []byte(mockCA), Mode: 0o644},
				} {
					data, err := os.ReadFile(filepath.Join(hostRootMount, path))
					assert.NoError(err)
					assert.Equal(string(file.Data), string(data))
					info, err := os.Stat(filepath.Join(hostRootMount, path))
					if assert.NoError(err) {
						assert.Equal(file.Mode, info.Mode())
					}
				}

				info, err = os.Stat(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o600), info.Mode())
				}

				kubeconfig, err := clientcmd.LoadFromFile(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
				assert.NoError(err)
				current := kubeconfig.Contexts[kubeconfig.CurrentContext]
				assert.Equal("https://10.96.0.1:443", kubeconfig.Clusters[current.Cluster].Server)
				assert.Equal("/run/nydus-snapshotter/kubernetes/ca.crt", kubeconfig.Clusters[current.Cluster].CertificateAuthority)
				assert.Equal("/run/nydus-snapshotter/kubernetes/token", kubeconfig.AuthInfos[current.AuthInfo].TokenFile)
			},
		},
		{
			name: "write kubeconfig where the config says",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {
				cfg.Auth.KubeSecret.Kubeconfig = "/var/lib/kubernetes/nydus/kubeconfig"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for path, file := range map[string]fstest.MapFile{
					"var/lib/kubernetes/nydus/token":  {Data: []byte(mockToken), Mode: 0o600},
					"var/lib/kubernetes/nydus/ca.crt": {Data: []byte(mockCA), Mode: 0o644},
				} {
					data, err := os.ReadFile(filepath.Join(hostRootMount, path))
					assert.NoError(err)
					assert.Equal(string(file.Data), string(data))
					info, err := os.Stat(filepath.Join(hostRootMount, path))
					if assert.NoError(err) {
						assert.Equal(file.Mode, info.Mode())
					}
				}

				kubeconfig, err := clientcmd.LoadFromFile(filepath.Join(hostRootMount, "var/lib/kubernetes/nydus/kubeconfig"))
				assert.NoError(err)
				current := kubeconfig.Contexts[kubeconfig.CurrentContext]
				assert.Equal("/var/lib/kubernetes/nydus/ca.crt", kubeconfig.Clusters[current.Cluster].CertificateAuthority)
				assert.Equal("/var/lib/kubernetes/nydus/token", kubeconfig.AuthInfos[current.AuthInfo].TokenFile)
				assert.NoFileExists(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "rotate token",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {
				i, err := New(cfg, config.DefaultPath, nil)
				if err != nil {
					t.Fatal(err)
				}

				assert.NoError(t, i.syncKubeconfig(t.Context()))
				assert.NoError(t, os.WriteFile(filepath.Join(cfg.Installer.ServiceAccountPath, "token"), []byte("rotated"), 0o600))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(hostRootMount, mockHostTokenPath))
				assert.NoError(err)
				assert.Equal("rotated", string(data))
				info, err := os.Stat(filepath.Join(hostRootMount, mockHostTokenPath))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o600), info.Mode())
				}
			},
		},
		{
			name:    "ipv6 service host",
			host:    "fd00::1",
			prepare: func(t *testing.T, cfg *config.Config) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				kubeconfig, err := clientcmd.LoadFromFile(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
				assert.NoError(err)
				assert.Equal("https://[fd00::1]:443", kubeconfig.Clusters["default"].Server)
			},
		},
		{
			name:    "not in cluster",
			host:    "",
			prepare: func(t *testing.T, cfg *config.Config) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.NoFileExists(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "missing token",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Remove(filepath.Join(cfg.Installer.ServiceAccountPath, "token")))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "missing ca",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Remove(filepath.Join(cfg.Installer.ServiceAccountPath, "ca.crt")))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read service account ca")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
			},
		},
		{
			name: "host directory that cannot be created",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.CopyFS(hostRootMount, fstest.MapFS{"run/nydus-snapshotter/kubernetes": {}}))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create "+filepath.Join(hostRootMount, filepath.Dir(config.DefaultAuthKubeconfig)))
			},
		},
		{
			name: "host path that cannot be resolved",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Symlink("run", filepath.Join(hostRootMount, "run")))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path "+filepath.Dir(config.DefaultAuthKubeconfig))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !testRoot {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(hostRootMount))
			assert.NoError(t, os.MkdirAll(hostRootMount, 0o755))
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			cfg := config.New()
			cfg.Installer.ServiceAccountPath = t.TempDir()
			assert.NoError(t, os.CopyFS(cfg.Installer.ServiceAccountPath, mockServiceAccount))
			tc.prepare(t, cfg)

			i, err := New(cfg, config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, i.syncKubeconfig(t.Context()))
		})
	}
}
