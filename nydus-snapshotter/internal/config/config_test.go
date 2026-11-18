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
				assert.Equal("ondemand", cfg.Nydusd.PrefetchScope)
				assert.Equal("debug", cfg.Nydusd.LogLevel)
				assert.Equal(3, cfg.Nydusd.LogMaxFiles)
				assert.Equal(Duration(time.Minute), cfg.Nydusd.WatchdogTimeout)
				assert.Equal("http://dragonfly-scheduler.dragonfly-system.svc:8002", cfg.Nydusd.Dragonfly.SchedulerEndpoint)
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
				assert.Nil(cfg)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(tc.path)
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
			data: "nydusd:\n  dragonfly:\n    scheduler_endpoint: \"http://scheduler:8002\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockSchedulerEndpoint, cfg.Nydusd.Dragonfly.SchedulerEndpoint)
				assert.Equal(DefaultNydusdDragonflyRequestTimeout, cfg.Nydusd.Dragonfly.RequestTimeout)
				assert.Equal(DefaultNydusdDragonflyMaxRetries, cfg.Nydusd.Dragonfly.MaxRetries)
				assert.Equal(DefaultNydusdDragonflyFallbackRateLimit, cfg.Nydusd.Dragonfly.FallbackRateLimit)
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
			data: "version: 1\n---\nroot: /var/lib/other\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "more than one YAML document")
			},
		},
		{
			name: "config that does not validate",
			data: "version: 2\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported config version 2")
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
			name:   "unsupported version",
			mutate: func(cfg *Config) { cfg.Version = 2 },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported config version 2")
			},
		},
		{
			name:   "relative root",
			mutate: func(cfg *Config) { cfg.Root = "var/lib" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "root must be an absolute path")
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
			name:   "address over sun_path",
			mutate: func(cfg *Config) { cfg.Address = "/run/" + strings.Repeat("x", 110) + ".sock" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "address")
			},
		},
		{
			name:   "daemon api socket over sun_path",
			mutate: func(cfg *Config) { cfg.RunDir = "/run/" + strings.Repeat("x", 40) },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "run_dir")
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
			mutate: func(cfg *Config) { cfg.Metrics.Address = "not-an-address" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid metrics.address")
			},
		},
		{
			name:   "metrics disabled",
			mutate: func(cfg *Config) { cfg.Metrics.Address = "" },
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
			mutate: func(cfg *Config) { cfg.Nydusd.PrefetchScope = "some" },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid nydusd.prefetch_scope")
			},
		},
		{
			name:   "dragonfly without a scheduler is not checked",
			mutate: func(cfg *Config) { cfg.Nydusd.Dragonfly = NydusdDragonflyConfig{} },
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "dragonfly request timeout that is not positive",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Dragonfly.SchedulerEndpoint, cfg.Nydusd.Dragonfly.RequestTimeout = mockSchedulerEndpoint, 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.dragonfly.request_timeout must be positive")
			},
		},
		{
			name: "dragonfly retries over the limit",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Dragonfly.SchedulerEndpoint, cfg.Nydusd.Dragonfly.MaxRetries = mockSchedulerEndpoint, 4
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.dragonfly.max_retries must be within [0, 3]")
			},
		},
		{
			name: "dragonfly fallback rate limit under one",
			mutate: func(cfg *Config) {
				cfg.Nydusd.Dragonfly.SchedulerEndpoint, cfg.Nydusd.Dragonfly.FallbackRateLimit = mockSchedulerEndpoint, 0
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.dragonfly.fallback_rate_limit must be at least 1")
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
				assert.Equal("/run/nydus-snapshotter/nydusd/"+id, cfg.RuntimeDir(id))
				assert.Equal("/var/lib/nydus-snapshotter/nydusd/"+id, cfg.InstanceDir(id))
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
			name: "apply cgroup limits and dragonfly",
			update: func(next *Config) {
				next.Cgroup.MemoryMax = 4 << 30
				next.Nydusd.Dragonfly.SchedulerEndpoint = "http://scheduler:8002"
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.False(restartOnly)
				assert.Equal(Size(4<<30), merged.Cgroup.MemoryMax)
				assert.Equal("http://scheduler:8002", merged.Nydusd.Dragonfly.SchedulerEndpoint)
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
			name: "defer settings that need a restart",
			update: func(next *Config) {
				next.Root = "/var/lib/other"
				next.Log.Level = "debug"
			},
			expect: func(t *testing.T, running, merged *Config, restartOnly bool) {
				assert := assert.New(t)
				assert.True(restartOnly)
				assert.Equal(running.Root, merged.Root)
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
