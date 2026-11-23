/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"regexp"
	"time"

	"github.com/containerd/containerd/v2/defaults"
)

const (
	// DriverFUSE is the FUSE mount driver.
	DriverFUSE = "fuse"
)

const (
	// maxSocketPath is the length limit of a unix socket path (sun_path).
	maxSocketPath = 107

	// daemonIDLength is the length of a daemon ID, the hex of a sha256 chain
	// ID.
	daemonIDLength = 64

	// maxDragonflyRetries is the retry limit nydus accepts for Dragonfly
	// reads, refer to the Registry backend section of docs/nydus.md.
	maxDragonflyRetries = 3

	// minMountTimeout is the shortest mount timeout: systemd counts a unit's
	// stop timeout in microseconds and reads zero as none.
	minMountTimeout = time.Second

	// minWatchdogTimeout is the shortest watchdog timeout: a daemon sends a
	// keep-alive every half of it, and a shorter one would have systemd kill
	// a healthy daemon over a scheduling delay.
	minWatchdogTimeout = 10 * time.Second
)

const (
	// DefaultPath is the default config file path.
	DefaultPath = "/etc/nydus-snapshotter/config.yaml"

	// DefaultRootDir is the default directory of persistent data: snapshots,
	// the cache and daemon instances.
	DefaultRootDir = "/var/lib/nydus-snapshotter"

	// DefaultRuntimeDir is the default directory of transient data, on tmpfs:
	// daemon API sockets and rendered configs, which carry credentials and
	// must not reach disk.
	DefaultRuntimeDir = "/run/nydus-snapshotter"

	// DefaultGRPCAddr is the default gRPC socket containerd connects to.
	DefaultGRPCAddr = "/run/nydus-snapshotter/nydus-snapshotter.sock"

	// DefaultLogLevel is the default log level.
	DefaultLogLevel = "info"

	// DefaultMetricsAddr is the default metrics address.
	DefaultMetricsAddr = "127.0.0.1:4010"

	// DefaultRegistryConfigPath is the default certs.d directory.
	DefaultRegistryConfigPath = "/etc/nydus-snapshotter/certs.d"

	// DefaultAuthKubeconfig is the kubeconfig the installer keeps in sync. It
	// names the service account token, so it lives on tmpfs.
	DefaultAuthKubeconfig = "/run/nydus-snapshotter/kubernetes/kubeconfig"
)

const (
	// DefaultNydusdBinary is the nydus binary the installer points at the
	// current version.
	DefaultNydusdBinary = "/opt/nydus-snapshotter/bin/current/nydus"

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

	// DefaultNydusdMountTimeout bounds a daemon start, a unit job and a mount
	// wait.
	DefaultNydusdMountTimeout = Duration(10 * time.Second)
)

const (
	// DefaultNydusdRuntimeDir is nydus's default runtime directory.
	DefaultNydusdRuntimeDir = "/run/nydus"

	// DefaultNydusdHTTPRequestTimeout is nydus's default timeout of a request
	// to the origin registry, its body included.
	DefaultNydusdHTTPRequestTimeout = Duration(time.Minute)

	// DefaultNydusdHTTPRequestReadTimeout is nydus's default read timeout of
	// a request to the origin registry.
	DefaultNydusdHTTPRequestReadTimeout = Duration(5 * time.Second)

	// DefaultNydusdHTTPMaxRetries is nydus's default retry count of a request
	// to the origin registry.
	DefaultNydusdHTTPMaxRetries = 3

	// DefaultNydusdDragonflyRequestTimeout is nydus's default timeout of each
	// attempt of a request through seed peers, its body included, refer to
	// the Dragonfly section of docs/nydus.md.
	DefaultNydusdDragonflyRequestTimeout = Duration(time.Minute)

	// DefaultNydusdDragonflyRequestReadTimeout is nydus's default wait of an
	// on-demand read for a seed peer.
	DefaultNydusdDragonflyRequestReadTimeout = Duration(5 * time.Second)

	// DefaultNydusdDragonflyMaxRetries is nydus's default retry count of an
	// on-demand read through seed peers.
	DefaultNydusdDragonflyMaxRetries = 1

	// DefaultNydusdFallbackRequestTimeout is nydus's default timeout of a
	// request the fallback sends to the origin, its body included.
	DefaultNydusdFallbackRequestTimeout = Duration(time.Minute)

	// DefaultNydusdFallbackRequestReadTimeout is nydus's default read timeout
	// of a request the fallback sends to the origin.
	DefaultNydusdFallbackRequestReadTimeout = Duration(5 * time.Second)

	// DefaultNydusdFallbackMaxRetries is nydus's default retry count of a
	// request the fallback sends to the origin.
	DefaultNydusdFallbackMaxRetries = 0

	// DefaultNydusdFallbackRateLimit is nydus's default rate of the origin
	// requests on-demand reads fall back to, in requests per second.
	DefaultNydusdFallbackRateLimit = 1

	// DefaultNydusdStorageFetchSize is nydus's default compressed bytes one
	// on-demand read covers, 2 MiB.
	DefaultNydusdStorageFetchSize = 2 << 20

	// DefaultNydusdPrefetchConcurrentBlobCount is nydus's default number of
	// blobs prefetched at once.
	DefaultNydusdPrefetchConcurrentBlobCount = 10

	// DefaultNydusdPrefetchRequestTimeout is nydus's default timeout of
	// prefetching one whole blob.
	DefaultNydusdPrefetchRequestTimeout = Duration(time.Hour)

	// DefaultNydusdPrefetchRetryInterval is nydus's default wait before a
	// failed prefetch read is sent once more.
	DefaultNydusdPrefetchRetryInterval = Duration(6 * time.Hour)

	// DefaultNydusdPrefetchScope is the default prefetch scope of a daemon.
	DefaultNydusdPrefetchScope = "auto"
)

const (
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
)

const (
	// DefaultGCInterval is the default cache GC interval, as dfdaemon's.
	DefaultGCInterval = Duration(15 * time.Minute)

	// DefaultGCBlobTTL is the default cache TTL of an unused blob.
	DefaultGCBlobTTL = Duration(30 * 24 * time.Hour)

	// DefaultGCDiskHighThresholdPercent starts disk watermark eviction.
	DefaultGCDiskHighThresholdPercent = 80

	// DefaultGCDiskLowThresholdPercent stops disk watermark eviction.
	DefaultGCDiskLowThresholdPercent = 60
)

const (
	// DefaultPreheatMaxConcurrentImages is the number of images preheated at
	// once by default, as kubelet pulls images one at a time by default.
	DefaultPreheatMaxConcurrentImages = 1

	// DefaultPreheatContainerdAddr is containerd's own default socket.
	DefaultPreheatContainerdAddr = defaults.DefaultAddress
)

const (
	// DefaultInstallerRootfsDir is where the DaemonSet mounts the root
	// filesystem of the host.
	DefaultInstallerRootfsDir = "/host"

	// DefaultInstallerPayloadDir holds what the image ships to install: bin/
	// and systemd/.
	DefaultInstallerPayloadDir = "/opt/nydus-snapshotter/payload"

	// DefaultInstallerTokenDir is the Pod's projected service account token
	// directory.
	DefaultInstallerTokenDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	// DefaultInstallerSyncInterval is how often the installer syncs, well
	// within the hour a projected token lives.
	DefaultInstallerSyncInterval = Duration(time.Minute)

	// DefaultInstallerContainerdAddr is containerd's own default socket.
	DefaultInstallerContainerdAddr = defaults.DefaultAddress
)

var (
	// PrefetchScopes are the prefetch scopes nydusd accepts.
	PrefetchScopes = []string{"none", "ondemand", "all", "auto"}

	// nydusdLogLevels are the log levels nydusd accepts.
	nydusdLogLevels = []string{"trace", "debug", "info", "warn", "error"}

	// sliceRegexp matches a slice unit name, refer to
	// https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html.
	sliceRegexp = regexp.MustCompile(`^[0-9A-Za-z:_\\-][0-9A-Za-z:_.\\-]*\.slice$`)
)
