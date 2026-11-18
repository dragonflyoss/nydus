/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import "time"

const (
	// DefaultPath is the default config file path.
	DefaultPath = "/etc/nydus-snapshotter/config.yaml"

	// DefaultRoot is the default root directory of snapshots, the cache and
	// daemon instances.
	DefaultRoot = "/var/lib/nydus-snapshotter"

	// DefaultAddress is the default gRPC socket containerd connects to.
	DefaultAddress = "/run/nydus-snapshotter/nydus-snapshotter.sock"

	// DefaultRunDir is the tmpfs directory holding daemon API sockets and
	// rendered configs, which carry credentials and must not reach disk.
	DefaultRunDir = "/run/nydus-snapshotter"

	// DefaultLogLevel is the default log level.
	DefaultLogLevel = "info"

	// DefaultMetricsAddress is the default metrics and health address.
	DefaultMetricsAddress = "127.0.0.1:4010"

	// DefaultRegistryConfigPath is the default certs.d directory.
	DefaultRegistryConfigPath = "/etc/nydus-snapshotter/certs.d"

	// DefaultAuthKubeconfig is the kubeconfig the installer keeps in sync. It
	// names the service account token, so it lives on tmpfs.
	DefaultAuthKubeconfig = "/run/nydus-snapshotter/kubernetes/kubeconfig"

	// DefaultNydusdBinary is the nydus binary the installer points at the
	// current version.
	DefaultNydusdBinary = "/opt/nydus-snapshotter/bin/current/nydus"

	// DefaultNydusdTemplate is the default nydusd config template.
	DefaultNydusdTemplate = "/etc/nydus-snapshotter/nydusd.template.yaml"

	// DefaultNydusdLogDir is the default parent of per-daemon log dirs.
	DefaultNydusdLogDir = "/var/log/nydus-snapshotter/nydusd"

	// DefaultNydusdLogLevel is the default log level of a daemon.
	DefaultNydusdLogLevel = "info"

	// DefaultNydusdLogMaxFiles is the number of log files a daemon keeps by
	// default, nydus's own default.
	DefaultNydusdLogMaxFiles = 6

	// DefaultNydusdWatchdogTimeout is the default watchdog timeout of a
	// daemon, the one systemd gives its own daemons, refer to
	// https://github.com/systemd/systemd/blob/main/units/systemd-journald.service.in.
	DefaultNydusdWatchdogTimeout = Duration(3 * time.Minute)

	// DefaultNydusdPrefetchScope is the default prefetch scope of a daemon.
	DefaultNydusdPrefetchScope = "auto"

	// DefaultNydusdMountTimeout bounds a daemon start, a unit job and a mount
	// wait.
	DefaultNydusdMountTimeout = Duration(10 * time.Second)

	// DefaultCgroupSlice is the slice daemons run in, named as systemd names
	// the slice of a service's instances, refer to systemd.slice(5).
	DefaultCgroupSlice = "system-nydusd.slice"

	// DefaultCgroupMemoryMax is the default memory.max of all daemons.
	DefaultCgroupMemoryMax = Size(8 << 30)

	// DefaultCgroupMemoryHigh is the default memory.high of all daemons.
	DefaultCgroupMemoryHigh = Size(6 << 30)

	// DefaultCgroupCPUQuota is the default CPU quota of all daemons, four
	// CPUs.
	DefaultCgroupCPUQuota = CPUQuota(400)

	// DefaultCgroupDaemonMemoryHigh is the default memory.high of one daemon.
	DefaultCgroupDaemonMemoryHigh = Size(1 << 30)

	// DefaultCgroupDaemonCPUQuota is the default CPU quota of one daemon, one
	// CPU. nydus sizes its thread pools by the CPUs it may use, so a daemon
	// without a quota starts a thread per CPU of the node.
	DefaultCgroupDaemonCPUQuota = CPUQuota(100)

	// DefaultNydusdDragonflyRequestTimeout is nydus's default timeout of a
	// request through seed peers, refer to the Dragonfly section of
	// docs/nydus.md.
	DefaultNydusdDragonflyRequestTimeout = Duration(5 * time.Second)

	// DefaultNydusdDragonflyMaxRetries is nydus's default retry count of an
	// on-demand read through seed peers.
	DefaultNydusdDragonflyMaxRetries = 1

	// DefaultNydusdDragonflyFallbackRateLimit is nydus's default origin
	// fallback rate in requests per second.
	DefaultNydusdDragonflyFallbackRateLimit = 1

	// DefaultGCInterval is the default cache GC interval, as dfdaemon's.
	DefaultGCInterval = Duration(15 * time.Minute)

	// DefaultGCBlobTTL is the default cache TTL of an unused blob.
	DefaultGCBlobTTL = Duration(30 * 24 * time.Hour)

	// DefaultGCDiskHighThresholdPercent starts disk watermark eviction.
	DefaultGCDiskHighThresholdPercent = 80

	// DefaultGCDiskLowThresholdPercent stops disk watermark eviction.
	DefaultGCDiskLowThresholdPercent = 60
)

// New returns a config holding the defaults.
func New() *Config {
	return &Config{
		Version: Version,
		Root:    DefaultRoot,
		Address: DefaultAddress,
		RunDir:  DefaultRunDir,
		Log: LogConfig{
			Level: DefaultLogLevel,
		},
		Metrics: MetricsConfig{
			Address: DefaultMetricsAddress,
		},
		Registry: RegistryConfig{
			ConfigPath: DefaultRegistryConfigPath,
		},
		Auth: AuthConfig{
			KubeSecret: AuthKubeSecretConfig{
				Kubeconfig: DefaultAuthKubeconfig,
			},
		},
		Nydusd: NydusdConfig{
			Driver:          DriverFUSE,
			Binary:          DefaultNydusdBinary,
			Template:        DefaultNydusdTemplate,
			LogDir:          DefaultNydusdLogDir,
			LogLevel:        DefaultNydusdLogLevel,
			LogMaxFiles:     DefaultNydusdLogMaxFiles,
			MountTimeout:    DefaultNydusdMountTimeout,
			WatchdogTimeout: DefaultNydusdWatchdogTimeout,
			PrefetchScope:   DefaultNydusdPrefetchScope,
			Dragonfly: NydusdDragonflyConfig{
				RequestTimeout:    DefaultNydusdDragonflyRequestTimeout,
				MaxRetries:        DefaultNydusdDragonflyMaxRetries,
				FallbackRateLimit: DefaultNydusdDragonflyFallbackRateLimit,
			},
		},
		Cgroup: CgroupConfig{
			Slice:      DefaultCgroupSlice,
			MemoryMax:  DefaultCgroupMemoryMax,
			MemoryHigh: DefaultCgroupMemoryHigh,
			CPUQuota:   DefaultCgroupCPUQuota,
			Daemon: CgroupDaemonConfig{
				MemoryHigh: DefaultCgroupDaemonMemoryHigh,
				CPUQuota:   DefaultCgroupDaemonCPUQuota,
			},
		},
		GC: GCConfig{
			Interval: DefaultGCInterval,
			Policy: GCPolicyConfig{
				BlobTTL:                  DefaultGCBlobTTL,
				DiskHighThresholdPercent: DefaultGCDiskHighThresholdPercent,
				DiskLowThresholdPercent:  DefaultGCDiskLowThresholdPercent,
			},
		},
	}
}
