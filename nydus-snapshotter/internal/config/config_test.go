/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Load(t *testing.T) {
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
				assert.Equal("http://dragonfly-scheduler.dragonfly-system.svc:8002", cfg.Nydusd.Dragonfly.SchedulerEndpoint)
				assert.Equal(Size(8<<30), cfg.Cgroup.MemoryMax)
				assert.Equal(Percent(400), cfg.Cgroup.CPUQuota)
				assert.Equal(uint64(4_000_000), cfg.Cgroup.CPUQuota.CPUQuotaPerSecUSec())
				assert.Equal(Size(1<<30), cfg.Cgroup.Daemon.MemoryHigh)
				assert.Equal(Duration(720*time.Hour), cfg.GC.Policy.BlobTTL)
			},
		},
		{
			name: "missing file uses defaults",
			path: "testdata/missing.yaml",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(New(), cfg)
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

func TestConfig_Parse(t *testing.T) {
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
			name: "unknown key",
			data: "nydusd:\n  unknown: 1\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "decode config")
			},
		},
		{
			name: "unsupported version",
			data: "version: 2\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "unsupported config version 2")
			},
		},
		{
			name: "relative root",
			data: "root: \"var/lib\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "root must be an absolute path")
			},
		},
		{
			name: "unsupported driver",
			data: "nydusd:\n  driver: \"ublk\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "unsupported nydusd.driver")
			},
		},
		{
			name: "invalid prefetch scope",
			data: "nydusd:\n  prefetch_scope: \"some\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "invalid nydusd.prefetch_scope")
			},
		},
		{
			name: "invalid duration",
			data: "nydusd:\n  mount_timeout: \"soon\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "parse duration")
			},
		},
		{
			name: "invalid size",
			data: "cgroup:\n  memory_max: \"lots\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "parse size")
			},
		},
		{
			name: "cpu quota without percent sign",
			data: "cgroup:\n  cpu_quota: \"400\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "missing %")
			},
		},
		{
			name: "slice without suffix",
			data: "cgroup:\n  slice: \"nydus\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "invalid cgroup.slice")
			},
		},
		{
			name: "low watermark above high",
			data: "gc:\n  policy:\n    disk_high_threshold_percent: 50\n    disk_low_threshold_percent: 70\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "invalid gc.policy thresholds")
			},
		},
		{
			name: "invalid label selector",
			data: "auth:\n  kubesecret:\n    label_selector: \"a in (\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "invalid auth.kubesecret.label_selector")
			},
		},
		{
			name: "dragonfly retries over the limit",
			data: "nydusd:\n  dragonfly:\n    scheduler_endpoint: \"http://scheduler:8002\"\n    request_timeout: \"5s\"\n    max_retries: 4\n    fallback_rate_limit: 1\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "nydusd.dragonfly.max_retries")
			},
		},
		{
			name: "scheduler endpoint alone takes nydus's dragonfly defaults",
			data: "nydusd:\n  dragonfly:\n    scheduler_endpoint: \"http://scheduler:8002\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(DefaultDragonflyRequestTimeout, cfg.Nydusd.Dragonfly.RequestTimeout)
				assert.Equal(DefaultDragonflyMaxRetries, cfg.Nydusd.Dragonfly.MaxRetries)
				assert.Equal(DefaultDragonflyFallbackRateLimit, cfg.Nydusd.Dragonfly.FallbackRateLimit)
			},
		},
		{
			name: "percent out of range",
			data: "cgroup:\n  cpu_quota: \"1844674407370956%\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "out of range")
			},
		},
		{
			name: "relative docker config path",
			data: "auth:\n  docker_config:\n    path: \"config.json\"\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "auth.docker_config.path must be an absolute path")
			},
		},
		{
			name: "socket path over sun_path",
			data: "run_dir: /run/" + strings.Repeat("x", 40) + "\n",
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.ErrorContains(t, err, "byte limit")
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
				assert.Equal("/run/containerd-nydus-v3/nydusd/"+id+".sock", cfg.APISocket(id))
				assert.Equal(101, len(cfg.APISocket(id)))
				assert.Equal("/run/containerd-nydus-v3/nydusd/"+id, cfg.RuntimeDir(id))
				assert.Equal("/var/lib/containerd-nydus-v3/nydusd/"+id, cfg.InstanceDir(id))
				assert.Equal("/var/lib/containerd-nydus-v3/cache", cfg.CacheDir())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, New())
		})
	}
}

func TestWatcher_Run(t *testing.T) {
	tests := []struct {
		name   string
		update string
		expect func(t *testing.T, reloaded <-chan *Config)
	}{
		{
			name:   "reload a changed config",
			update: "cgroup:\n  memory_max: \"4GiB\"\n",
			expect: func(t *testing.T, reloaded <-chan *Config) {
				assert := assert.New(t)
				select {
				case cfg := <-reloaded:
					assert.Equal(Size(4<<30), cfg.Cgroup.MemoryMax)
				case <-time.After(5 * time.Second):
					assert.Fail("config not reloaded")
				}
			},
		},
		{
			name:   "keep the running config on an invalid change",
			update: "cgroup:\n  memory_max: \"lots\"\n",
			expect: func(t *testing.T, reloaded <-chan *Config) {
				select {
				case <-reloaded:
					assert.Fail(t, "invalid config reloaded")
				case <-time.After(200 * time.Millisecond):
				}
			},
		},
		{
			name:   "ignore a rewrite of the running config",
			update: "version: 1\n\n",
			expect: func(t *testing.T, reloaded <-chan *Config) {
				select {
				case <-reloaded:
					assert.Fail(t, "unchanged config reloaded")
				case <-time.After(200 * time.Millisecond):
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			tmp := path + ".tmp"
			assert.NoError(t, os.WriteFile(tmp, []byte(tc.update), 0o644))
			reloaded := make(chan *Config, 1)
			w := NewWatcher(path, 10*time.Millisecond, New())
			go w.Run(t.Context(), func(_ context.Context, cfg *Config) { reloaded <- cfg })
			assert.NoError(t, os.Rename(tmp, path))
			tc.expect(t, reloaded)
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

func TestCgroupConfig_ParentSlice(t *testing.T) {
	tests := []struct {
		name   string
		slice  string
		expect func(t *testing.T, slice string)
	}{
		{
			name:  "nested slice",
			slice: "system-nydus-v3.slice",
			expect: func(t *testing.T, slice string) {
				assert.Equal(t, "system-nydus.slice", slice)
			},
		},
		{
			name:  "top level slice",
			slice: "nydusv3.slice",
			expect: func(t *testing.T, slice string) {
				assert.Equal(t, "nydusv3.slice", slice)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &CgroupConfig{Slice: tc.slice}
			tc.expect(t, cfg.ParentSlice())
		})
	}
}
