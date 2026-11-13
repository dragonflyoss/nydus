/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

var (
	mockAuth = base64.StdEncoding.EncodeToString([]byte("user:secret"))
)

func TestBasicAuthConfig(t *testing.T) {
	assert := assert.New(t)
	auth := basicAuthConfig("user", "pass")
	assert.Equal("dXNlcjpwYXNz", auth)

	out, err := yaml.Marshal(storageConfig{
		Backend: backendSection{
			Type: "registry",
			Config: registryBackendConfig{
				Addr:       "https://reg.example.com",
				Repository: "library/ubuntu",
				Auth:       auth,
			},
		},
	})
	assert.NoError(err)

	var decoded struct {
		Backend struct {
			Config struct {
				Auth any `yaml:"auth"`
			} `yaml:"config"`
		} `yaml:"backend"`
	}
	assert.NoError(yaml.Unmarshal(out, &decoded))
	assert.Equal("dXNlcjpwYXNz", decoded.Backend.Config.Auth)
}

func TestWriteRegistryConfig(t *testing.T) {
	tests := []struct {
		name       string
		opt        remote.Option
		ref        string
		env        map[string]string
		prefetch   bool
		configPath string
		expect     func(t *testing.T, cacheDir, configPath, out string, err error)
	}{
		{
			name:       "plain http registry with credentials and prefetch",
			opt:        remote.Option{TargetPlainHTTP: true},
			ref:        "registry.test/ns/image:v1",
			prefetch:   true,
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				written, err := os.ReadFile(configPath)
				assert.NoError(err)
				assert.Equal(out, string(written))

				var cfg storageConfig
				assert.NoError(yaml.Unmarshal(written, &cfg))
				assert.Equal(storageConfig{
					Backend: backendSection{
						Type: "registry",
						Config: registryBackendConfig{
							Addr:       "http://registry.test",
							Repository: "ns/image",
							Auth:       mockAuth,
						},
					},
					Storage:  storageSection{Dir: cacheDir},
					Prefetch: prefetchSection{Scope: "ondemand"},
				}, cfg)
			},
		},
		{
			name:       "docker hub over insecure tls",
			opt:        remote.Option{TargetInsecure: true},
			ref:        "busybox",
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var cfg storageConfig
				assert.NoError(yaml.Unmarshal([]byte(out), &cfg))
				assert.Equal("https://registry-1.docker.io", cfg.Backend.Config.Addr)
				assert.Equal("library/busybox", cfg.Backend.Config.Repository)
				assert.Empty(cfg.Backend.Config.Auth)
				assert.True(cfg.Backend.Config.HTTP.TLS.SkipVerify)
				assert.Equal("none", cfg.Prefetch.Scope)
			},
		},
		{
			name:       "invalid image reference",
			ref:        "Registry.test/Image:v1",
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse image reference "Registry.test/Image:v1"`)
				assert.Empty(out)
				assert.NoFileExists(configPath)
			},
		},
		{
			name:       "config directory missing",
			ref:        "registry.test/ns/image:v1",
			configPath: filepath.Join("missing", "config.yaml"),
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write storage config")
				assert.Empty(out)
			},
		},
		{
			name:       "proxy of a tls registry",
			ref:        "registry.test/ns/image:v1",
			env:        map[string]string{"HTTPS_PROXY": "http://user:pass@proxy.test:3128", "HTTP_PROXY": "http://plain.test:3128"},
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var decoded struct {
					Backend struct {
						Config struct {
							HTTP struct {
								Proxy map[string]string `yaml:"proxy"`
							} `yaml:"http"`
						} `yaml:"config"`
					} `yaml:"backend"`
				}
				assert.NoError(yaml.Unmarshal([]byte(out), &decoded))
				assert.Equal(map[string]string{"addr": "http://user:pass@proxy.test:3128"}, decoded.Backend.Config.HTTP.Proxy)
			},
		},
		{
			name:       "proxy of a plain http registry",
			opt:        remote.Option{TargetPlainHTTP: true},
			ref:        "registry.test:5000/ns/image:v1",
			env:        map[string]string{"HTTPS_PROXY": "http://tls.test:3128", "HTTP_PROXY": "https://proxy.test"},
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var cfg storageConfig
				assert.NoError(yaml.Unmarshal([]byte(out), &cfg))
				assert.Equal(&proxySection{Addr: "https://proxy.test"}, cfg.Backend.Config.HTTP.Proxy)
			},
		},
		{
			name:       "registry excluded by NO_PROXY",
			ref:        "registry.test/ns/image:v1",
			env:        map[string]string{"HTTPS_PROXY": "http://proxy.test:3128", "NO_PROXY": "other.test,registry.test"},
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotContains(out, "proxy:")
			},
		},
		{
			name:       "proxy the daemon cannot use",
			ref:        "registry.test/ns/image:v1",
			env:        map[string]string{"HTTPS_PROXY": "socks5://proxy.test:1080"},
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotContains(out, "proxy:")
			},
		},
		{
			name:       "proxy the environment forbids",
			opt:        remote.Option{TargetPlainHTTP: true},
			ref:        "registry.test/ns/image:v1",
			env:        map[string]string{"HTTP_PROXY": "http://proxy.test:3128", "REQUEST_METHOD": "GET"},
			configPath: "config.yaml",
			expect: func(t *testing.T, cacheDir, configPath, out string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `resolve the proxy of "http://registry.test" from the environment`)
				assert.Empty(out)
				assert.NoFileExists(configPath)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
				t.Setenv(key, tc.env[key])
			}

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"auths":{"registry.test":{"auth":"`+mockAuth+`"}}}`), 0o600); err != nil {
				t.Fatal(err)
			}

			previous := dockerconfig.Dir()
			dockerconfig.SetDir(dir)
			t.Cleanup(func() { dockerconfig.SetDir(previous) })

			tc.opt.WorkDir = t.TempDir()
			provider, err := remote.NewProvider(tc.opt)
			if err != nil {
				t.Fatal(err)
			}

			configPath := filepath.Join(dir, tc.configPath)
			cacheDir := filepath.Join(dir, "cache")
			out, err := WriteRegistryConfig(provider, remote.Target, &Image{Ref: tc.ref}, cacheDir, configPath, tc.prefetch)

			tc.expect(t, cacheDir, configPath, out, err)
		})
	}
}

func TestRegistryBackendConfigDragonfly(t *testing.T) {
	assert := assert.New(t)
	render := func(df *dragonflySection) string {
		out, err := yaml.Marshal(storageConfig{Backend: backendSection{
			Type:   "registry",
			Config: registryBackendConfig{Addr: "https://reg.example.com", Dragonfly: df},
		}})
		assert.NoError(err)
		return string(out)
	}

	assert.NotContains(render(nil), "dragonfly")
	out := render(&dragonflySection{SchedulerEndpoint: "http://127.0.0.1:8002"})
	assert.Contains(out, "dragonfly:\n")
	assert.Contains(out, "scheduler_endpoint: http://127.0.0.1:8002")
}
