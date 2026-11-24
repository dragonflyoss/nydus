/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var mockSchedulerEndpoint = "http://scheduler:8002"

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, cfg *Config)
	}{
		{
			name: "defaults validate",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				assert.NoError(cfg.Validate())
			},
		},
		{
			name: "shipped config states the defaults",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				shipped := New()
				assert.NoError(shipped.Load("../../deploy/nydus-snapshotter/config.yaml"))
				assert.Equal(cfg, shipped)
			},
		},
		{
			name: "every call returns a config of its own",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				cfg.RootDir = "/var/lib/other"
				assert.Equal(DefaultRootDir, New().RootDir)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, New())
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect func(t *testing.T, cfg *Config, err error)
	}{
		{
			name: "load full config",
			path: "testdata/config.yaml",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("debug", cfg.Log.Level)
				assert.True(cfg.Auth.KubeSecret.Enable)
				assert.Equal("app=cr-credential", cfg.Auth.KubeSecret.LabelSelector)
				assert.Equal(Duration(20*time.Second), cfg.Nydusd.MountTimeout)
				assert.Equal("/run/nydus-other", cfg.Nydusd.Config.RuntimeDir)
				assert.Equal(NydusdStorageConfig{Dir: "/data/nydus-cache", SkipVerifyChecksums: true, FetchSize: 4 << 20}, cfg.Nydusd.Config.Storage)
				assert.Equal("/data/nydus-cache", cfg.CacheDir())
				assert.Equal(NydusdPrefetchConfig{ConcurrentBlobCount: 4, RequestTimeout: Duration(2 * time.Hour), RetryInterval: Duration(3 * time.Hour), Scope: "ondemand"}, cfg.Nydusd.Config.Prefetch)
				assert.Equal("debug", cfg.Nydusd.LogLevel)
				assert.Equal(3, cfg.Nydusd.LogMaxFiles)
				assert.Equal(Duration(time.Minute), cfg.Nydusd.WatchdogTimeout)
				assert.Equal("http://dragonfly-scheduler.dragonfly-system.svc:8002", cfg.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint)
				assert.Equal(Duration(30*time.Second), cfg.Nydusd.Config.Backend.Config.Dragonfly.RequestTimeout)
				assert.Equal(Duration(5*time.Second), cfg.Nydusd.Config.Backend.Config.Dragonfly.RequestReadTimeout)
				assert.Equal(NydusdHTTPConfig{RequestTimeout: Duration(2 * time.Minute), RequestReadTimeout: Duration(10 * time.Second), MaxRetries: 5, Proxy: NydusdProxyConfig{Addr: "http://127.0.0.1:65001"}}, cfg.Nydusd.Config.Backend.Config.HTTP)
				assert.Equal(NydusdFallbackConfig{RequestTimeout: Duration(45 * time.Second), RequestReadTimeout: Duration(4 * time.Second), MaxRetries: 2, RateLimit: 2}, cfg.Nydusd.Config.Backend.Config.Fallback)
				assert.Equal(Size(8<<30), cfg.Cgroup.MemoryMax)
				assert.Equal(CPUQuota(400), cfg.Cgroup.CPUQuota)
				assert.Equal(uint64(4_000_000), cfg.Cgroup.CPUQuota.PerSecUSec())
				assert.Equal(Size(1<<30), cfg.Cgroup.Daemon.MemoryHigh)
				assert.Equal(Duration(720*time.Hour), cfg.GC.Policy.BlobTTL)
			},
		},
		{
			name: "missing file",
			path: "testdata/missing.yaml",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Equal(New(), cfg)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := New()
			err := cfg.Load(tc.path)
			tc.expect(t, cfg, err)
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		expect func(t *testing.T, cfg *Config, err error)
	}{
		{
			name: "empty config uses defaults",
			data: "",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(New(), cfg)
			},
		},
		{
			name: "set keys keep the defaults of the others",
			data: "nydusd:\n  config:\n    backend:\n      config:\n        dragonfly:\n          scheduler_endpoint: \"http://scheduler:8002\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockSchedulerEndpoint, cfg.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint)
				assert.Equal(DefaultNydusdDragonflyRequestTimeout, cfg.Nydusd.Config.Backend.Config.Dragonfly.RequestTimeout)
				assert.Equal(DefaultNydusdDragonflyMaxRetries, cfg.Nydusd.Config.Backend.Config.Dragonfly.MaxRetries)
				assert.Equal(DefaultNydusdDragonflyRequestReadTimeout, cfg.Nydusd.Config.Backend.Config.Dragonfly.RequestReadTimeout)
				assert.Equal(New().Nydusd.Config.Backend.Config.HTTP, cfg.Nydusd.Config.Backend.Config.HTTP)
				assert.Equal(New().Nydusd.Config.Backend.Config.Fallback, cfg.Nydusd.Config.Backend.Config.Fallback)
			},
		},
		{
			name: "unknown key",
			data: "nydusd:\n  unknown: 1\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode config")
				assert.Nil(cfg)
			},
		},
		{
			name: "value of the wrong form",
			data: "nydusd:\n  mount_timeout: \"soon\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode config")
				assert.ErrorContains(err, "parse duration")
			},
		},
		{
			name: "second document",
			data: "log:\n  level: info\n---\nroot_dir: /var/lib/other\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "more than one YAML document")
			},
		},
		{
			name: "config that does not validate",
			data: "log:\n  level: loud\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
				assert.Nil(cfg)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.data))
			tc.expect(t, cfg, err)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(cfg *Config)
		expect func(t *testing.T, err error)
	}{
		{
			name:   "defaults",
			mutate: func(cfg *Config) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "relative root",
			mutate: func(cfg *Config) { cfg.RootDir = "var/lib" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "root_dir must be an absolute path")
			},
		},
		{
			name:   "relative docker config path",
			mutate: func(cfg *Config) { cfg.Auth.DockerConfig.Path = "config.json" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "auth.docker_config.path must be an absolute path")
			},
		},
		{
			name:   "registry config path list",
			mutate: func(cfg *Config) { cfg.Registry.ConfigPath = "/etc/containerd/certs.d:/etc/docker/certs.d" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "relative path in the registry config path list",
			mutate: func(cfg *Config) { cfg.Registry.ConfigPath = "/etc/containerd/certs.d:certs.d" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "registry.config_path must hold absolute paths")
			},
		},
		{
			name:   "grpc socket over sun_path",
			mutate: func(cfg *Config) { cfg.GRPC.Addr = "/run/" + strings.Repeat("x", 110) + ".sock" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "grpc.addr ")
			},
		},
		{
			name:   "daemon api socket over sun_path",
			mutate: func(cfg *Config) { cfg.RuntimeDir = "/run/" + strings.Repeat("x", 40) },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "runtime_dir ")
			},
		},
		{
			name:   "invalid log level",
			mutate: func(cfg *Config) { cfg.Log.Level = "verbose" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
			},
		},
		{
			name:   "invalid metrics address",
			mutate: func(cfg *Config) { cfg.Metrics.Addr = "not-an-address" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid metrics.addr")
			},
		},
		{
			name:   "metrics disabled",
			mutate: func(cfg *Config) { cfg.Metrics.Addr = "" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "invalid label selector",
			mutate: func(cfg *Config) { cfg.Auth.KubeSecret.LabelSelector = "a in (" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid auth.kube_secret.label_selector")
			},
		},
		{
			name:   "unsupported driver",
			mutate: func(cfg *Config) { cfg.Nydusd.Driver = "ublk" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported nydusd.driver")
			},
		},
		{
			name:   "invalid daemon log level",
			mutate: func(cfg *Config) { cfg.Nydusd.LogLevel = "verbose" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid nydusd.log_level")
			},
		},
		{
			name:   "no daemon log file",
			mutate: func(cfg *Config) { cfg.Nydusd.LogMaxFiles = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.log_max_files must be at least 1")
			},
		},
		{
			name:   "mount timeout under a second",
			mutate: func(cfg *Config) { cfg.Nydusd.MountTimeout = Duration(time.Nanosecond) },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.mount_timeout must be at least 1s")
			},
		},
		{
			name:   "watchdog timeout a daemon cannot keep",
			mutate: func(cfg *Config) { cfg.Nydusd.WatchdogTimeout = Duration(time.Second) },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.watchdog_timeout must be 0 or at least 10s")
			},
		},
		{
			name:   "watchdog disabled",
			mutate: func(cfg *Config) { cfg.Nydusd.WatchdogTimeout = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "invalid prefetch scope",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Prefetch.Scope = "some" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid nydusd.config.prefetch.scope")
			},
		},
		{
			name:   "prefetch blob count below one",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Prefetch.ConcurrentBlobCount = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.prefetch.concurrent_blob_count must be at least 1")
			},
		},
		{
			name:   "prefetch request timeout that is not positive",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Prefetch.RequestTimeout = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.prefetch.request_timeout must be positive")
			},
		},
		{
			name:   "prefetch retry interval that is negative",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Prefetch.RetryInterval = Duration(-time.Second) },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.prefetch.retry_interval must not be negative")
			},
		},
		{
			name:   "nydusd runtime dir that is relative",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.RuntimeDir = "run/nydus" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.runtime_dir must be an absolute path")
			},
		},
		{
			name:   "storage dir that is relative",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Storage.Dir = "cache" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.storage.dir must be an absolute path")
			},
		},
		{
			name:   "proxy address with a scheme and a host",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Backend.Config.HTTP.Proxy.Addr = "http://127.0.0.1:65001" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "proxy address without a scheme is not echoed",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Backend.Config.HTTP.Proxy.Addr = "user:p@127.0.0.1:65001" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "nydusd.config.backend.config.http.proxy.addr must be a URL with a scheme and a host")
			},
		},
		{
			name:   "dragonfly without a scheduler is not checked",
			mutate: func(cfg *Config) { cfg.Nydusd.Config.Backend.Config.Dragonfly = NydusdDragonflyConfig{} },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "dragonfly request timeout that is not positive",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint, cfg.Nydusd.Config.Backend.Config.Dragonfly.RequestTimeout = mockSchedulerEndpoint, 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.dragonfly.request_timeout must be positive")
			},
		},
		{
			name: "dragonfly retries over the limit",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint, cfg.Nydusd.Config.Backend.Config.Dragonfly.MaxRetries = mockSchedulerEndpoint, 4
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.dragonfly.max_retries must be within [0, 3]")
			},
		},
		{
			name: "dragonfly request read timeout that is not positive",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint, cfg.Nydusd.Config.Backend.Config.Dragonfly.RequestReadTimeout = mockSchedulerEndpoint, 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.dragonfly.request_read_timeout must be positive")
			},
		},
		{
			name: "fallback rate limit below one",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.Fallback.RateLimit = 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.fallback.rate_limit must be at least 1")
			},
		},
		{
			name: "http request timeout that is not positive",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.HTTP.RequestTimeout = 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.http.request_timeout must be positive")
			},
		},
		{
			name: "http request read timeout that is not positive",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.HTTP.RequestReadTimeout = 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.http.request_read_timeout must be positive")
			},
		},
		{
			name: "negative http retries",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.HTTP.MaxRetries = -1
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.http.max_retries must not be negative")
			},
		},
		{
			name: "fallback request timeout that is not positive",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Config.Backend.Config.Fallback.RequestTimeout = 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.config.backend.config.fallback.request_timeout must be positive")
			},
		},
		{
			name:   "slice without suffix",
			mutate: func(cfg *Config) { cfg.Cgroup.Slice = "nydus" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid cgroup.slice")
			},
		},
		{
			name:   "slice with a path separator",
			mutate: func(cfg *Config) { cfg.Cgroup.Slice = "a/b.slice" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid cgroup.slice")
			},
		},
		{
			name:   "slice without a name",
			mutate: func(cfg *Config) { cfg.Cgroup.Slice = ".slice" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid cgroup.slice")
			},
		},
		{
			name:   "gc interval that is not positive",
			mutate: func(cfg *Config) { cfg.GC.Interval = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "gc.interval must be positive")
			},
		},
		{
			name:   "blob ttl that is not positive",
			mutate: func(cfg *Config) { cfg.GC.Policy.BlobTTL = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "gc.policy.blob_ttl must be positive")
			},
		},
		{
			name: "low watermark above high",
			mutate: func(cfg *Config) {
				cfg.GC.Policy.DiskHighThresholdPercent, cfg.GC.Policy.DiskLowThresholdPercent = 50, 70
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid gc.policy thresholds: low 70%, high 50%")
			},
		},
		{
			name:   "high watermark over 99",
			mutate: func(cfg *Config) { cfg.GC.Policy.DiskHighThresholdPercent = 100 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid gc.policy thresholds")
			},
		},
		{
			name:   "preheat containerd addr that is relative",
			mutate: func(cfg *Config) { cfg.Preheat.ContainerdAddr = "containerd.sock" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `preheat.containerd_addr must be an absolute path, got "containerd.sock"`)
			},
		},
		{
			name:   "preheat max concurrent images that is not positive",
			mutate: func(cfg *Config) { cfg.Preheat.MaxConcurrentImages = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "preheat.max_concurrent_images must be positive")
			},
		},
		{
			name:   "installer rootfs dir that is relative",
			mutate: func(cfg *Config) { cfg.Installer.RootfsDir = "host" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `installer.rootfs_dir must be an absolute path, got "host"`)
			},
		},
		{
			name:   "installer payload dir that is relative",
			mutate: func(cfg *Config) { cfg.Installer.PayloadDir = "payload" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `installer.payload_dir must be an absolute path, got "payload"`)
			},
		},
		{
			name:   "installer token dir that is empty",
			mutate: func(cfg *Config) { cfg.Installer.TokenDir = "" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `installer.token_dir must be an absolute path, got ""`)
			},
		},
		{
			name:   "installer certs dir that is relative",
			mutate: func(cfg *Config) { cfg.Installer.CertsDir = "certs.d" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `installer.certs_dir must be an absolute path, got "certs.d"`)
			},
		},
		{
			name:   "installer containerd addr that is relative",
			mutate: func(cfg *Config) { cfg.Installer.NodeLabel.ContainerdAddr = "containerd.sock" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `installer.node_label.containerd_addr must be an absolute path, got "containerd.sock"`)
			},
		},
		{
			name:   "installer sync interval that is not positive",
			mutate: func(cfg *Config) { cfg.Installer.SyncInterval = 0 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "installer.sync_interval must be positive")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := New()
			tc.mutate(cfg)
			tc.expect(t, cfg.Validate())
		})
	}
}

func TestConfig_Paths(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, cfg *Config)
	}{
		{
			name: "default daemon paths",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				id := strings.Repeat("a", 64)
				assert.Equal("/run/nydus-snapshotter/nydusd/"+id+".sock", cfg.APISocket(id))
				assert.Len(cfg.APISocket(id), 99)
				assert.Equal("/run/nydus-snapshotter/nydusd/"+id, cfg.DaemonRuntimeDir(id))
				assert.Equal("/var/lib/nydus-snapshotter/nydusd/"+id, cfg.DaemonInstanceDir(id))
				assert.Equal("/var/lib/nydus-snapshotter/cache", cfg.CacheDir())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, New())
		})
	}
}

func TestConfig_Merge(t *testing.T) {
	tests := []struct {
		name   string
		update func(next *Config)
		expect func(t *testing.T, running, merged *Config, restartOnly bool)
	}{
		{
			name: "apply cgroup limits and the daemon config",
			update: func(next *Config) {
				next.Cgroup.MemoryMax = 4 << 30
				next.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint = "http://scheduler:8002"
				next.Nydusd.Config.Backend.Config.Fallback.RateLimit = 5
				next.Nydusd.Config.Storage.FetchSize = 4 << 20
				next.Nydusd.Config.Prefetch.ConcurrentBlobCount = 4
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.False(restartOnly)
				assert.Equal(Size(4<<30), merged.Cgroup.MemoryMax)
				assert.Equal("http://scheduler:8002", merged.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint)
				assert.Equal(5, merged.Nydusd.Config.Backend.Config.Fallback.RateLimit)
				assert.Equal(uint64(4<<20), merged.Nydusd.Config.Storage.FetchSize)
				assert.Equal(4, merged.Nydusd.Config.Prefetch.ConcurrentBlobCount)
			},
		},
		{
			name: "keep the directories of the running daemons",
			update: func(next *Config) {
				next.Nydusd.Config.Storage.Dir = "/data/nydus-cache"
				next.Nydusd.Config.RuntimeDir = "/run/nydus-other"
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.True(restartOnly)
				assert.Equal(running.CacheDir(), merged.CacheDir())
				assert.Equal(running.Nydusd.Config.RuntimeDir, merged.Nydusd.Config.RuntimeDir)
			},
		},
		{
			name: "keep the slice of the running daemons",
			update: func(next *Config) {
				next.Cgroup.Slice = "system-other.slice"
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.True(restartOnly)
				assert.Equal(running.Cgroup.Slice, merged.Cgroup.Slice)
			},
		},
		{
			name: "ignore the installer config",
			update: func(next *Config) {
				next.Installer.SyncInterval = Duration(time.Second)
				next.Installer.NodeLabel.Enable = true
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.False(restartOnly)
			},
		},
		{
			name: "defer settings that need a restart",
			update: func(next *Config) {
				next.RootDir = "/var/lib/other"
				next.Log.Level = "debug"
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.True(restartOnly)
				assert.Equal(running.RootDir, merged.RootDir)
				assert.Equal(running.Log.Level, merged.Log.Level)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			running, next := New(), New()
			tc.update(next)
			merged, restartOnly := running.Merge(next)
			tc.expect(t, running, merged, restartOnly)
		})
	}
}
