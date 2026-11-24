/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
	"gopkg.in/yaml.v3"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

func TestRenderOptions_render(t *testing.T) {
	tests := []struct {
		name   string
		opts   *renderOptions
		expect func(t *testing.T, rendered map[string]any, err error)
	}{
		{
			name: "render every section",
			opts: &renderOptions{
				nydusd: config.NydusdDaemonConfig{
					RuntimeDir: "/run/nydus",
					Backend: config.NydusdBackendConfig{
						Config: config.NydusdRegistryConfig{
							HTTP: config.NydusdHTTPConfig{
								RequestTimeout:     config.Duration(2 * time.Minute),
								RequestReadTimeout: config.Duration(10 * time.Second),
								MaxRetries:         5,
								Proxy:              config.NydusdProxyConfig{Addr: "http://127.0.0.1:65001"},
							},
							Dragonfly: config.NydusdDragonflyConfig{
								SchedulerEndpoint:  "http://scheduler:8002",
								RequestTimeout:     config.Duration(time.Minute),
								RequestReadTimeout: config.Duration(5 * time.Second),
								MaxRetries:         1,
							},
							Fallback: config.NydusdFallbackConfig{
								RequestTimeout:     config.Duration(45 * time.Second),
								RequestReadTimeout: config.Duration(4 * time.Second),
								RateLimit:          2,
							},
						},
					},
					Storage: config.NydusdStorageConfig{
						Dir:                 "/ignored",
						SkipVerifyChecksums: true,
						FetchSize:           4 << 20,
					},
					Prefetch: config.NydusdPrefetchConfig{
						ConcurrentBlobCount: 4,
						RequestTimeout:      config.Duration(2 * time.Hour),
						RetryInterval:       config.Duration(3 * time.Hour),
						Scope:               "auto",
					},
				},
				cacheDir:      "/var/lib/nydus-snapshotter/cache",
				addr:          "https://registry.example.com",
				repository:    "team/app",
				auth:          mockCredential,
				skipVerify:    true,
				caCert:        "/etc/nydus-snapshotter/certs.d/registry.example.com/ca.crt",
				prefetchScope: "none",
			},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]any{
					"runtime_dir": "/run/nydus",
					"backend": map[string]any{
						"type": "registry",
						"config": map[string]any{
							"addr":       "https://registry.example.com",
							"repository": "team/app",
							"auth":       mockCredential,
							"http": map[string]any{
								"request_timeout":      "2m0s",
								"request_read_timeout": "10s",
								"max_retries":          5,
								"proxy":                map[string]any{"addr": "http://127.0.0.1:65001"},
								"tls": map[string]any{
									"skip_verify": true,
									"ca_cert":     "/etc/nydus-snapshotter/certs.d/registry.example.com/ca.crt",
								},
							},
							"dragonfly": map[string]any{
								"scheduler_endpoint":   "http://scheduler:8002",
								"request_timeout":      "1m0s",
								"request_read_timeout": "5s",
								"max_retries":          1,
							},
							"fallback": map[string]any{
								"request_timeout":      "45s",
								"request_read_timeout": "4s",
								"max_retries":          0,
								"rate_limit":           2,
							},
						},
					},
					"storage": map[string]any{
						"dir":                   "/var/lib/nydus-snapshotter/cache",
						"skip_verify_checksums": true,
						"fetch_size":            4 << 20,
					},
					"prefetch": map[string]any{
						"concurrent_blob_count": 4,
						"request_timeout":       "2h0m0s",
						"retry_interval":        "3h0m0s",
						"scope":                 "none",
					},
				}, rendered)
			},
		},
		{
			name: "leave out a credential, proxy, tls and dragonfly that are not set",
			opts: &renderOptions{nydusd: config.New().Nydusd.Config, addr: "https://registry.example.com", repository: "team/app", prefetchScope: "auto"},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				registry := rendered["backend"].(map[string]any)["config"].(map[string]any)
				assert.NotContains(registry, "auth")
				assert.NotContains(registry, "registry_token")
				assert.NotContains(registry, "dragonfly")
				assert.NotContains(registry["http"], "proxy")
				assert.NotContains(registry["http"], "tls")
			},
		},
		{
			name: "render a bearer token without a basic credential",
			opts: &renderOptions{nydusd: config.New().Nydusd.Config, addr: "https://registry.example.com", repository: "team/app", registryToken: "token", prefetchScope: "auto"},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				registry := rendered["backend"].(map[string]any)["config"].(map[string]any)
				assert.Equal("token", registry["registry_token"])
				assert.NotContains(registry, "auth")
			},
		},
		{
			name: "render zero dragonfly retries",
			opts: &renderOptions{
				nydusd: config.NydusdDaemonConfig{
					Backend: config.NydusdBackendConfig{
						Config: config.NydusdRegistryConfig{
							Dragonfly: config.NydusdDragonflyConfig{
								SchedulerEndpoint:  "http://scheduler:8002",
								RequestTimeout:     config.Duration(time.Minute),
								RequestReadTimeout: config.Duration(5 * time.Second),
							},
						},
					},
				},
			},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				dragonfly := rendered["backend"].(map[string]any)["config"].(map[string]any)["dragonfly"].(map[string]any)
				assert.Equal(0, dragonfly["max_retries"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.opts.render()
			rendered := map[string]any{}
			if err == nil {
				assert.NoError(t, yaml.Unmarshal(data, &rendered))
			}
			tc.expect(t, rendered, err)
		})
	}
}

func TestFileSystem_renderConfig(t *testing.T) {
	tests := []struct {
		name          string
		cas           []string
		prefetchScope string
		mock          func(m *authmocks.MockKeychainMockRecorder)
		prepare       func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon)
		expect        func(t *testing.T, d *Daemon, rendered map[string]any, err error)
	}{
		{
			name:          "label prefetch scope and one ca",
			cas:           []string{"ca.crt"},
			prefetchScope: "none",
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("none", rendered["prefetch"].(map[string]any)["scope"])
				tls := rendered["backend"].(map[string]any)["config"].(map[string]any)["http"].(map[string]any)["tls"].(map[string]any)
				assert.Equal("ca.crt", filepath.Base(tls["ca_cert"].(string)))
			},
		},
		{
			name: "configured prefetch scope and a bundle of cas",
			cas:  []string{"a.crt", "b.crt"},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(config.DefaultNydusdPrefetchScope, rendered["prefetch"].(map[string]any)["scope"])
				tls := rendered["backend"].(map[string]any)["config"].(map[string]any)["http"].(map[string]any)["tls"].(map[string]any)
				bundle, err := os.ReadFile(tls["ca_cert"].(string))
				assert.NoError(err)
				assert.Equal("a.crt\nb.crt\n", string(bundle))
				assert.Equal(d.RuntimeDir, filepath.Dir(tls["ca_cert"].(string)))
			},
		},
		{
			name: "registry host config that is invalid",
			mock: func(m *authmocks.MockKeychainMockRecorder) {},
			prepare: func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon) {
				assert.NoError(t, os.WriteFile(filepath.Join(hostDir, "hosts.toml"), []byte("server = ["), 0o644))
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "hosts.toml")
				assert.NoFileExists(d.ConfigPath)
			},
		},
		{
			name: "credential that cannot be resolved",
			mock: func(m *authmocks.MockKeychainMockRecorder) {
				m.Resolve(gomock.Any(), gomock.Any()).Return("", errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "resolve credential of registry.example.com/team/app:v1-nydus-v3: foo")
				assert.NoFileExists(d.ConfigPath)
			},
		},
		{
			name: "ca that cannot be read",
			cas:  []string{"a.crt"},
			prepare: func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon) {
				assert.NoError(t, os.Symlink("missing", filepath.Join(hostDir, "b.crt")))
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read ca ")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(d.ConfigPath)
			},
		},
		{
			name: "runtime dir that does not exist",
			prepare: func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon) {
				assert.NoError(t, os.Remove(d.RuntimeDir))
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "runtime dir that does not exist for a bundle of cas",
			cas:  []string{"a.crt", "b.crt"},
			prepare: func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon) {
				assert.NoError(t, os.Remove(d.RuntimeDir))
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			keychain := authmocks.NewMockKeychain(ctl)
			if tc.mock == nil {
				keychain.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
			} else {
				tc.mock(keychain.EXPECT())
			}

			driver := NewMockDriver(ctl)
			driver.EXPECT().Name().Return(config.DriverFUSE).AnyTimes()

			f, image := newTestFileSystem(t, systemdmocks.NewMockSystemd(ctl), keychain, driver, nydusdmocks.NewMockClient(ctl))
			cfg := f.cfg.Load()
			cfg.Registry.ConfigPath = t.TempDir()
			hostDir := filepath.Join(cfg.Registry.ConfigPath, "registry.example.com")
			assert.NoError(t, os.MkdirAll(hostDir, 0o755))
			for _, ca := range tc.cas {
				assert.NoError(t, os.WriteFile(filepath.Join(hostDir, ca), []byte(ca), 0o644))
			}
			f.hosts = registry.NewHosts(cfg.Registry.ConfigPath)

			ref, err := registry.ParseReference(image.Ref)
			assert.NoError(t, err)
			id, err := daemonIDFromChainID(image.ChainID)
			assert.NoError(t, err)
			d := f.daemon(cfg, id)
			assert.NoError(t, os.MkdirAll(d.RuntimeDir, 0o700))
			if tc.prepare != nil {
				tc.prepare(t, cfg, hostDir, d)
			}

			err = f.renderConfig(t.Context(), cfg, d, ref, tc.prefetchScope)
			rendered := map[string]any{}
			if err == nil {
				data, readErr := os.ReadFile(d.ConfigPath)
				assert.NoError(t, readErr)
				assert.NoError(t, yaml.Unmarshal(data, &rendered))
			}
			tc.expect(t, d, rendered, err)
		})
	}
}
