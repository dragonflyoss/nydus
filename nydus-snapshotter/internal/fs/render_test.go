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
		name     string
		template string
		opts     *renderOptions
		expect   func(t *testing.T, rendered map[string]any, err error)
	}{
		{
			name:     "fill registry, tls, dragonfly and prefetch",
			template: mockTemplate,
			opts: &renderOptions{
				cacheDir:      "/var/lib/nydus-snapshotter/cache",
				addr:          "https://registry.example.com",
				repository:    "team/app",
				auth:          mockCredential,
				skipVerify:    true,
				caCert:        "/etc/nydus-snapshotter/certs.d/registry.example.com/ca.crt",
				prefetchScope: "none",
				dragonfly: config.NydusdDragonflyConfig{
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
					"storage": map[string]any{"dir": "/var/lib/nydus-snapshotter/cache"},
					"prefetch": map[string]any{
						"concurrent_blob_count": 4,
						"scope":                 "none",
					},
					"backend": map[string]any{
						"type": "registry",
						"config": map[string]any{
							"addr":       "https://registry.example.com",
							"repository": "team/app",
							"auth":       mockCredential,
							"http": map[string]any{
								"request_timeout": "5s",
								"tls": map[string]any{
									"skip_verify": true,
									"ca_cert":     "/etc/nydus-snapshotter/certs.d/registry.example.com/ca.crt",
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
				dragonfly: config.NydusdDragonflyConfig{
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
				assert := assert.New(t)
				assert.ErrorContains(err, "backend is string, want a mapping")
			},
		},
		{
			name:     "fill sections the template leaves empty",
			template: "storage:\nprefetch:\nbackend:\n",
			opts:     &renderOptions{cacheDir: "/cache", addr: "https://registry.example.com", repository: "team/app", prefetchScope: "all"},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/cache", rendered["storage"].(map[string]any)["dir"])
				assert.Equal("all", rendered["prefetch"].(map[string]any)["scope"])
				assert.Equal("team/app", rendered["backend"].(map[string]any)["config"].(map[string]any)["repository"])
			},
		},
		{
			name:     "template that is no yaml",
			template: "backend: [\n",
			opts:     &renderOptions{},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode nydusd template")
			},
		},
		{
			name:     "storage is not a mapping",
			template: "storage: /cache\n",
			opts:     &renderOptions{},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "storage is string, want a mapping")
			},
		},
		{
			name:     "prefetch is not a mapping",
			template: "prefetch: true\n",
			opts:     &renderOptions{},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "prefetch is bool, want a mapping")
			},
		},
		{
			name:     "backend config is not a mapping",
			template: "backend:\n  config: [registry]\n",
			opts:     &renderOptions{},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "config is []interface {}, want a mapping")
			},
		},
		{
			name:     "http is not a mapping",
			template: "backend:\n  config:\n    http: 5s\n",
			opts:     &renderOptions{skipVerify: true},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "http is string, want a mapping")
			},
		},
		{
			name:     "tls is not a mapping",
			template: "backend:\n  config:\n    http:\n      tls: 1\n",
			opts:     &renderOptions{caCert: "/etc/ca.crt"},
			expect: func(t *testing.T, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "tls is int, want a mapping")
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

func TestDocument_child(t *testing.T) {
	tests := []struct {
		name   string
		doc    document
		expect func(t *testing.T, doc, child document, err error)
	}{
		{
			name: "create an absent mapping",
			doc:  document{},
			expect: func(t *testing.T, doc, child document, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				child["key"] = true
				assert.Equal(document{"a": document{"key": true}}, doc)
			},
		},
		{
			name: "create a mapping left empty",
			doc:  document{"a": nil},
			expect: func(t *testing.T, doc, child document, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				child["key"] = true
				assert.Equal(document{"a": document{"key": true}}, doc)
			},
		},
		{
			name: "keep a document",
			doc:  document{"a": document{"kept": true}},
			expect: func(t *testing.T, doc, child document, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(document{"kept": true}, child)
			},
		},
		{
			name: "keep a plain mapping",
			doc:  document{"a": map[string]any{"kept": true}},
			expect: func(t *testing.T, doc, child document, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				child["key"] = true
				assert.Equal(document{"a": document{"kept": true, "key": true}}, doc)
			},
		},
		{
			name: "value that is no mapping",
			doc:  document{"a": "value"},
			expect: func(t *testing.T, doc, child document, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "nydusd template: a is string, want a mapping")
				assert.Nil(child)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			child, err := tc.doc.child("a")
			tc.expect(t, tc.doc, child, err)
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
			name: "template that cannot be read",
			mock: func(m *authmocks.MockKeychainMockRecorder) {},
			prepare: func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon) {
				assert.NoError(t, os.Remove(cfg.Nydusd.Template))
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read nydusd template")
				assert.NoFileExists(d.ConfigPath)
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
			name: "template section that is no mapping",
			prepare: func(t *testing.T, cfg *config.Config, hostDir string, d *Daemon) {
				assert.NoError(t, os.WriteFile(cfg.Nydusd.Template, []byte("backend: registry\n"), 0o644))
			},
			expect: func(t *testing.T, d *Daemon, rendered map[string]any, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "backend is string, want a mapping")
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
