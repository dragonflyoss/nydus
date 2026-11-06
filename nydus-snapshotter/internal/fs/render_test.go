/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
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
		name     string
		template string
		opts     *renderOptions
		expect   func(t *testing.T, rendered map[string]any, err error)
	}{
		{
			name:     "fill registry, tls, dragonfly and prefetch",
			template: mockTemplate,
			opts: &renderOptions{
				cacheDir:      "/var/lib/containerd-nydus-v3/cache",
				addr:          "https://registry.example.com",
				repository:    "team/app",
				auth:          "dXNlcjpwYXNz",
				skipVerify:    true,
				caCert:        "/etc/nydus-v3/certs.d/registry.example.com/ca.crt",
				prefetchScope: "none",
				dragonfly: config.DragonflyConfig{
					SchedulerEndpoint: "http://scheduler:8002",
					RequestTimeout:    config.Duration(5 * time.Second),
					MaxRetries:        1,
					FallbackRateLimit: 1,
				},
			},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]any{
					"storage": map[string]any{"dir": "/var/lib/containerd-nydus-v3/cache"},
					"prefetch": map[string]any{
						"concurrent_blob_count": 4,
						"scope":                 "none",
					},
					"backend": map[string]any{
						"type": "registry",
						"config": map[string]any{
							"addr":       "https://registry.example.com",
							"repository": "team/app",
							"auth":       "dXNlcjpwYXNz",
							"http": map[string]any{
								"request_timeout": "5s",
								"tls": map[string]any{
									"skip_verify": true,
									"ca_cert":     "/etc/nydus-v3/certs.d/registry.example.com/ca.crt",
								},
							},
							"dragonfly": map[string]any{
								"scheduler_endpoint":  "http://scheduler:8002",
								"request_timeout":     "5s",
								"max_retries":         1,
								"fallback_rate_limit": 1,
							},
						},
					},
				}, rendered)
			},
		},
		{
			name:     "anonymous access drops a template credential",
			template: "backend:\n  config:\n    auth: c2VjcmV0\n",
			opts:     &renderOptions{addr: "https://registry.example.com", repository: "team/app", prefetchScope: "auto"},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				registry := rendered["backend"].(map[string]any)["config"].(map[string]any)
				assert.NotContains(registry, "auth")
				assert.NotContains(registry, "dragonfly")
				assert.NotContains(registry, "http")
			},
		},
		{
			name:     "render zero dragonfly retries",
			template: mockTemplate,
			opts: &renderOptions{
				dragonfly: config.DragonflyConfig{
					SchedulerEndpoint: "http://scheduler:8002",
					RequestTimeout:    config.Duration(5 * time.Second),
					FallbackRateLimit: 1,
				},
			},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				dragonfly := rendered["backend"].(map[string]any)["config"].(map[string]any)["dragonfly"].(map[string]any)
				assert.Equal(0, dragonfly["max_retries"])
			},
		},
		{
			name:     "template section is not a mapping",
			template: "backend: registry\n",
			opts:     &renderOptions{},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert.ErrorContains(t, err, "backend is string, want a mapping")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.opts.render([]byte(tc.template))
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
				assert.Equal(config.DefaultPrefetchScope, rendered["prefetch"].(map[string]any)["scope"])
				tls := rendered["backend"].(map[string]any)["config"].(map[string]any)["http"].(map[string]any)["tls"].(map[string]any)
				bundle, err := os.ReadFile(tls["ca_cert"].(string))
				assert.NoError(err)
				assert.Equal("a.crt\nb.crt\n", string(bundle))
				assert.Equal(filepath.Dir(d.Config), filepath.Dir(tls["ca_cert"].(string)))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			keychain := authmocks.NewMockKeychain(ctl)
			keychain.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return("dXNlcjpwYXNz", nil).Times(1)
			driver := NewMockDriver(ctl)
			driver.EXPECT().Name().Return(config.DriverFuse).AnyTimes()

			f, image := newTestFileSystem(t, systemdmocks.NewMockManager(ctl), keychain, driver, nydusdmocks.NewMockClient(ctl))
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
			id, err := parseDaemonID(image.ChainID)
			assert.NoError(t, err)
			d := f.daemon(cfg, id)
			assert.NoError(t, os.MkdirAll(filepath.Dir(d.Config), 0o700))

			err = f.renderConfig(t.Context(), cfg, d, ref, tc.prefetchScope)
			rendered := map[string]any{}
			if err == nil {
				data, readErr := os.ReadFile(d.Config)
				assert.NoError(t, readErr)
				assert.NoError(t, yaml.Unmarshal(data, &rendered))
			}
			tc.expect(t, d, rendered, err)
		})
	}
}
