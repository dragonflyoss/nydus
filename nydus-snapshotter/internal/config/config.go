/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package config defines the snapshotter configuration, its defaults and
// validation, decoded strictly from YAML with the snake_case keys of the
// nydus daemon config.
package config

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

// Config is the snapshotter config.
type Config struct {
	// path is the file the config was loaded from, which Reload reads again.
	path string

	// RootDir is the directory of persistent data: snapshots, the cache and
	// instances.
	RootDir string `yaml:"root_dir"`

	// RuntimeDir is the directory of transient data on tmpfs: daemon API
	// sockets and rendered configs, named as nydus-config names its own.
	RuntimeDir string `yaml:"runtime_dir"`

	// GRPC is the gRPC server config.
	GRPC GRPCConfig `yaml:"grpc"`

	// Log is the logging config.
	Log LogConfig `yaml:"log"`

	// Metrics is the metrics server config.
	Metrics MetricsConfig `yaml:"metrics"`

	// Containerd is the config of the containerd the snapshotter serves.
	Containerd ContainerdConfig `yaml:"containerd"`

	// Registry is the registry host config.
	Registry RegistryConfig `yaml:"registry"`

	// Auth is the registry credential config.
	Auth AuthConfig `yaml:"auth"`

	// Cgroup is the daemon resource config.
	Cgroup CgroupConfig `yaml:"cgroup"`

	// GC is the blob cache GC config.
	GC GCConfig `yaml:"gc"`

	// Preheat is the image preheat config.
	Preheat PreheatConfig `yaml:"preheat"`

	// Installer is the installer config, which the snapshotter ignores.
	Installer InstallerConfig `yaml:"installer"`

	// Nydusd is the daemon config.
	Nydusd NydusdConfig `yaml:"nydusd"`
}

// GRPCConfig is the gRPC server config, a section of its own as in
// containerd's and BuildKit's configs.
type GRPCConfig struct {
	// Addr is the unix socket path containerd connects to.
	Addr string `yaml:"addr"`
}

// LogConfig is the logging config.
type LogConfig struct {
	// Level is the log level, one logrus parses: trace, debug, info, warn or
	// error.
	Level string `yaml:"level"`
}

// MetricsConfig is the metrics server config.
type MetricsConfig struct {
	// Addr is the listen address of /metrics, empty to disable.
	Addr string `yaml:"addr"`
}

// ContainerdConfig is the config of the containerd the snapshotter serves.
type ContainerdConfig struct {
	// Addr is the socket of containerd. A preheat asks it for the layers of
	// an image, and the installer whether it loaded the snapshotter.
	Addr string `yaml:"addr"`
}

// RegistryConfig is the registry host config.
type RegistryConfig struct {
	// ConfigPath is the certs.d directory holding <host>/hosts.toml.
	ConfigPath string `yaml:"config_path"`
}

// AuthConfig is the registry credential config.
type AuthConfig struct {
	// DockerConfig is the docker config.json source, always on.
	DockerConfig AuthDockerConfig `yaml:"docker_config"`

	// KubeSecret is the Kubernetes secret source, optional.
	KubeSecret AuthKubeSecretConfig `yaml:"kube_secret"`
}

// AuthDockerConfig is the docker config.json source config.
type AuthDockerConfig struct {
	// Path is the config.json path, empty for kubelet's search order.
	Path string `yaml:"path"`
}

// AuthKubeSecretConfig is the Kubernetes secret source config.
type AuthKubeSecretConfig struct {
	// Enable turns on the secret informer.
	Enable bool `yaml:"enable"`

	// Kubeconfig is the kubeconfig path, empty for in-cluster config.
	Kubeconfig string `yaml:"kubeconfig"`

	// LabelSelector narrows the watched secrets.
	LabelSelector string `yaml:"label_selector"`
}

// CgroupConfig is the daemon resource config.
type CgroupConfig struct {
	// Slice is the slice daemons run in, which holds their total budget.
	Slice string `yaml:"slice"`

	// MemoryMax is the total memory.max of all daemons, 0 for no limit.
	MemoryMax Size `yaml:"memory_max"`

	// MemoryHigh is the total memory.high of all daemons, 0 for no limit.
	MemoryHigh Size `yaml:"memory_high"`

	// CPUQuota is the total CPU quota of all daemons, 0% for no limit.
	CPUQuota CPUQuota `yaml:"cpu_quota"`

	// Daemon is the per-daemon budget.
	Daemon CgroupDaemonConfig `yaml:"daemon"`
}

// CgroupDaemonConfig is the per-daemon resource config.
type CgroupDaemonConfig struct {
	// MemoryHigh is the per-daemon memory.high, 0 for no limit.
	MemoryHigh Size `yaml:"memory_high"`

	// CPUQuota is the per-daemon CPU quota, 0% for no limit.
	CPUQuota CPUQuota `yaml:"cpu_quota"`
}

// GCConfig is the blob cache GC config.
type GCConfig struct {
	// Interval is the GC interval.
	Interval Duration `yaml:"interval"`

	// Policy is the eviction policy.
	Policy GCPolicyConfig `yaml:"policy"`
}

// GCPolicyConfig is the blob cache eviction policy.
type GCPolicyConfig struct {
	// BlobTTL evicts blobs unused for longer.
	BlobTTL Duration `yaml:"blob_ttl"`

	// DiskThreshold is the capacity the percentages apply to, 0 for the
	// whole filesystem.
	DiskThreshold Size `yaml:"disk_threshold"`

	// DiskHighThresholdPercent starts watermark eviction.
	DiskHighThresholdPercent int `yaml:"disk_high_threshold_percent"`

	// DiskLowThresholdPercent stops watermark eviction.
	DiskLowThresholdPercent int `yaml:"disk_low_threshold_percent"`
}

// PreheatConfig is the image preheat config. A preheat downloads every blob
// of an image containerd has pulled, refer to the Preheat section of
// docs/snapshotter.md.
type PreheatConfig struct {
	// MaxConcurrentImages is the number of images preheated at once, the rest
	// wait.
	MaxConcurrentImages int `yaml:"max_concurrent_images"`
}

// InstallerConfig is the config of the installer, the DaemonSet Pod that
// installs the snapshotter onto the host, read once when it starts. It holds
// what every node shares.
type InstallerConfig struct {
	// ServiceAccountPath is where the Pod mounts its service account token
	// and CA.
	ServiceAccountPath string `yaml:"service_account_path"`

	// SyncInterval is how often the token and the config are copied to the
	// host and the node label is checked.
	SyncInterval Duration `yaml:"sync_interval"`

	// Registries is the registries config of the installer.
	Registries InstallerRegistriesConfig `yaml:"registries"`

	// NodeLabel is the node label config.
	NodeLabel InstallerNodeLabelConfig `yaml:"node_label"`
}

// InstallerRegistriesConfig is the registries config of the installer.
type InstallerRegistriesConfig struct {
	// Enable installs the certs.d of the ConfigMap to the host, where
	// registry.config_path reads it. Without it the host keeps its own.
	Enable bool `yaml:"enable"`
}

// InstallerNodeLabelConfig is the node label config of the installer.
type InstallerNodeLabelConfig struct {
	// Enable labels the node while its Pods can use the snapshotter. The
	// node is the one NODE_NAME names.
	Enable bool `yaml:"enable"`
}

// NydusdConfig is the daemon config.
type NydusdConfig struct {
	// Driver is the mount driver, only fuse today.
	Driver string `yaml:"driver"`

	// Binary is the nydus binary; symlinks are resolved when a daemon starts
	// so an upgrade never changes a running unit.
	Binary string `yaml:"binary"`

	// Log is the logging config of a daemon.
	Log NydusdLogConfig `yaml:"log"`

	// MountTimeout bounds a daemon start, a unit job and a mount wait.
	MountTimeout Duration `yaml:"mount_timeout"`

	// WatchdogTimeout is how long systemd waits for the keep-alive a daemon
	// sends before it takes the daemon for hung and kills it, 0 to disable.
	WatchdogTimeout Duration `yaml:"watchdog_timeout"`

	// Config is the config of each daemon.
	Config NydusdDaemonConfig `yaml:"config"`
}

// NydusdLogConfig is the logging config of a daemon, laid out as the
// snapshotter's own log section. A daemon logs to the journal, as the
// snapshotter does.
type NydusdLogConfig struct {
	// Level is the log level of a daemon: trace, debug, info, warn or
	// error.
	Level string `yaml:"level"`
}

// NydusdDaemonConfig is what the daemons' configs share. It mirrors
// nydus-config key for key; the rest of a daemon's config comes from its
// image and certs.d.
type NydusdDaemonConfig struct {
	// RuntimeDir is the runtime directory the daemons share.
	RuntimeDir string `yaml:"runtime_dir"`

	// Backend mirrors nydus-config's backend section.
	Backend NydusdBackendConfig `yaml:"backend"`

	// Storage mirrors nydus-config's storage section.
	Storage NydusdStorageConfig `yaml:"storage"`

	// Prefetch mirrors nydus-config's prefetch section.
	Prefetch NydusdPrefetchConfig `yaml:"prefetch"`
}

// NydusdStorageConfig mirrors nydus-config's storage section.
type NydusdStorageConfig struct {
	// Dir is the blob cache directory the daemons share, empty for
	// <root_dir>/cache.
	Dir string `yaml:"dir"`

	// SkipVerifyChecksums skips the crc32c check of decoded chunk groups.
	SkipVerifyChecksums bool `yaml:"skip_verify_checksums"`

	// FetchSize is the compressed bytes one on-demand read covers, 0 for the
	// missed chunk group alone.
	FetchSize uint64 `yaml:"fetch_size"`
}

// NydusdPrefetchConfig mirrors nydus-config's prefetch section.
type NydusdPrefetchConfig struct {
	// ConcurrentBlobCount is the number of blobs prefetched at once.
	ConcurrentBlobCount int `yaml:"concurrent_blob_count"`

	// RequestTimeout is the timeout of prefetching one whole blob.
	RequestTimeout Duration `yaml:"request_timeout"`

	// RetryInterval is the wait before a failed prefetch read is sent once
	// more, drawn between it and twice it.
	RetryInterval Duration `yaml:"retry_interval"`

	// Scope is the default prefetch scope, overridden per image by the
	// nydus-prefetch label.
	Scope string `yaml:"scope"`
}

// NydusdBackendConfig mirrors nydus-config's backend section, whose type is
// always registry.
type NydusdBackendConfig struct {
	// Config is the registry backend config.
	Config NydusdRegistryConfig `yaml:"config"`
}

// NydusdRegistryConfig mirrors the keys of nydus-config's backend.config
// that all daemons share; addr, repository, auth and http.tls come from the
// image and certs.d.
type NydusdRegistryConfig struct {
	// HTTP is merged into backend.config.http.
	HTTP NydusdHTTPConfig `yaml:"http"`

	// Dragonfly is copied into backend.config.dragonfly when set.
	Dragonfly NydusdDragonflyConfig `yaml:"dragonfly"`

	// Fallback is merged into backend.config.fallback.
	Fallback NydusdFallbackConfig `yaml:"fallback"`
}

// NydusdHTTPConfig is the HTTP client config of a daemon's requests to the
// origin registry, which mirrors nydus-config's backend.config.http.
type NydusdHTTPConfig struct {
	// RequestTimeout is the timeout of a request, its body included.
	RequestTimeout Duration `yaml:"request_timeout"`

	// RequestReadTimeout is the longest wait for the connection, the
	// response and each part of its body.
	RequestReadTimeout Duration `yaml:"request_read_timeout"`

	// MaxRetries is the retry count of a request; 0 is rendered, so it never
	// falls back to nydus's default.
	MaxRetries int `yaml:"max_retries"`

	// Proxy is the HTTP forward proxy of the requests.
	Proxy NydusdProxyConfig `yaml:"proxy"`
}

// NydusdProxyConfig mirrors nydus-config's backend.config.http.proxy.
type NydusdProxyConfig struct {
	// Addr is the proxy address with its scheme, empty to connect to the
	// origin.
	Addr string `yaml:"addr"`
}

// NydusdDragonflyConfig is the Dragonfly config of a daemon, which mirrors
// nydus-config's backend.config.dragonfly.
type NydusdDragonflyConfig struct {
	// SchedulerEndpoint is the Dragonfly scheduler address, empty to disable.
	SchedulerEndpoint string `yaml:"scheduler_endpoint"`

	// RequestTimeout is the timeout of each attempt of a request through
	// seed peers, its body included.
	RequestTimeout Duration `yaml:"request_timeout"`

	// RequestReadTimeout is the longest an on-demand read waits for a seed
	// peer before it goes to the origin.
	RequestReadTimeout Duration `yaml:"request_read_timeout"`

	// MaxRetries is the retry count of an on-demand read; 0 is rendered, so
	// it never falls back to nydus's default.
	MaxRetries int `yaml:"max_retries"`
}

// NydusdFallbackConfig is the origin fallback config of a daemon: the client
// an on-demand read falls back to when Dragonfly or the proxy cannot serve
// it. It mirrors nydus-config's backend.config.fallback.
type NydusdFallbackConfig struct {
	// RequestTimeout is the timeout of a request, its body included.
	RequestTimeout Duration `yaml:"request_timeout"`

	// RequestReadTimeout is the longest wait for the connection, the
	// response and each part of its body.
	RequestReadTimeout Duration `yaml:"request_read_timeout"`

	// MaxRetries is the retry count of a request; 0 is rendered, so it never
	// falls back to nydus's default.
	MaxRetries int `yaml:"max_retries"`

	// RateLimit is the rate of the origin requests in requests per second.
	RateLimit int `yaml:"rate_limit"`
}

// New returns a config holding the defaults.
func New() *Config {
	return &Config{
		RootDir:    DefaultRootDir,
		RuntimeDir: DefaultRuntimeDir,
		GRPC: GRPCConfig{
			Addr: DefaultGRPCAddr,
		},
		Log: LogConfig{
			Level: DefaultLogLevel,
		},
		Metrics: MetricsConfig{
			Addr: DefaultMetricsAddr,
		},
		Containerd: ContainerdConfig{
			Addr: DefaultContainerdAddr,
		},
		Registry: RegistryConfig{
			ConfigPath: DefaultRegistryConfigPath,
		},
		Auth: AuthConfig{
			KubeSecret: AuthKubeSecretConfig{
				Kubeconfig: DefaultAuthKubeconfig,
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
		Preheat: PreheatConfig{
			MaxConcurrentImages: DefaultPreheatMaxConcurrentImages,
		},
		Installer: InstallerConfig{
			ServiceAccountPath: DefaultInstallerServiceAccountPath,
			SyncInterval:       DefaultInstallerSyncInterval,
		},
		Nydusd: NydusdConfig{
			Driver: DriverFUSE,
			Binary: DefaultNydusdBinary,
			Log: NydusdLogConfig{
				Level: DefaultNydusdLogLevel,
			},
			MountTimeout:    DefaultNydusdMountTimeout,
			WatchdogTimeout: DefaultNydusdWatchdogTimeout,
			Config: NydusdDaemonConfig{
				RuntimeDir: DefaultNydusdRuntimeDir,
				Backend: NydusdBackendConfig{
					Config: NydusdRegistryConfig{
						HTTP: NydusdHTTPConfig{
							RequestTimeout:     DefaultNydusdHTTPRequestTimeout,
							RequestReadTimeout: DefaultNydusdHTTPRequestReadTimeout,
							MaxRetries:         DefaultNydusdHTTPMaxRetries,
						},
						Dragonfly: NydusdDragonflyConfig{
							RequestTimeout:     DefaultNydusdDragonflyRequestTimeout,
							RequestReadTimeout: DefaultNydusdDragonflyRequestReadTimeout,
							MaxRetries:         DefaultNydusdDragonflyMaxRetries,
						},
						Fallback: NydusdFallbackConfig{
							RequestTimeout:     DefaultNydusdFallbackRequestTimeout,
							RequestReadTimeout: DefaultNydusdFallbackRequestReadTimeout,
							MaxRetries:         DefaultNydusdFallbackMaxRetries,
							RateLimit:          DefaultNydusdFallbackRateLimit,
						},
					},
				},
				Storage: NydusdStorageConfig{
					FetchSize: DefaultNydusdStorageFetchSize,
				},
				Prefetch: NydusdPrefetchConfig{
					ConcurrentBlobCount: DefaultNydusdPrefetchConcurrentBlobCount,
					RequestTimeout:      DefaultNydusdPrefetchRequestTimeout,
					RetryInterval:       DefaultNydusdPrefetchRetryInterval,
					Scope:               DefaultNydusdPrefetchScope,
				},
			},
		},
	}
}

// Parse decodes a YAML config strictly over c and validates the result. An
// empty document keeps c as it is, and a config that fails leaves c half
// decoded.
func (c *Config) Parse(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config: %w", err)
	}

	// The keys of a second document would be dropped without a word.
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return errors.New("decode config: more than one YAML document")
	}

	return c.Validate()
}

// Validate config parameters.
func (c *Config) Validate() error {
	if !filepath.IsAbs(c.RootDir) {
		return fmt.Errorf("root_dir must be an absolute path, got %q", c.RootDir)
	}

	if !filepath.IsAbs(c.RuntimeDir) {
		return fmt.Errorf("runtime_dir must be an absolute path, got %q", c.RuntimeDir)
	}

	if socket := c.APISocket(strings.Repeat("0", daemonIDLength)); len(socket) > maxSocketPath {
		return fmt.Errorf("runtime_dir %q makes the daemon API socket %d bytes long, over the %d byte limit", c.RuntimeDir, len(socket), maxSocketPath)
	}

	if !filepath.IsAbs(c.GRPC.Addr) {
		return fmt.Errorf("grpc.addr must be an absolute path, got %q", c.GRPC.Addr)
	}

	if len(c.GRPC.Addr) > maxSocketPath {
		return fmt.Errorf("grpc.addr %q is %d bytes long, over the %d byte limit", c.GRPC.Addr, len(c.GRPC.Addr), maxSocketPath)
	}

	if _, err := logrus.ParseLevel(c.Log.Level); err != nil {
		return fmt.Errorf("invalid log.level: %w", err)
	}

	if c.Metrics.Addr != "" {
		if _, _, err := net.SplitHostPort(c.Metrics.Addr); err != nil {
			return fmt.Errorf("invalid metrics.addr: %w", err)
		}
	}

	if !filepath.IsAbs(c.Containerd.Addr) {
		return fmt.Errorf("containerd.addr must be an absolute path, got %q", c.Containerd.Addr)
	}

	if c.Registry.ConfigPath != "" {
		if !filepath.IsAbs(c.Registry.ConfigPath) {
			return fmt.Errorf("registry.config_path must be an absolute path, got %q", c.Registry.ConfigPath)
		}
	}

	if c.Auth.DockerConfig.Path != "" {
		if !filepath.IsAbs(c.Auth.DockerConfig.Path) {
			return fmt.Errorf("auth.docker_config.path must be an absolute path, got %q", c.Auth.DockerConfig.Path)
		}
	}

	if c.Auth.KubeSecret.Kubeconfig != "" {
		if !filepath.IsAbs(c.Auth.KubeSecret.Kubeconfig) {
			return fmt.Errorf("auth.kube_secret.kubeconfig must be an absolute path, got %q", c.Auth.KubeSecret.Kubeconfig)
		}
	}

	if _, err := labels.Parse(c.Auth.KubeSecret.LabelSelector); err != nil {
		return fmt.Errorf("invalid auth.kube_secret.label_selector: %w", err)
	}

	if !sliceRegexp.MatchString(c.Cgroup.Slice) {
		return fmt.Errorf("invalid cgroup.slice %q", c.Cgroup.Slice)
	}

	if c.GC.Interval <= 0 {
		return errors.New("gc.interval must be positive")
	}

	if c.GC.Policy.BlobTTL <= 0 {
		return errors.New("gc.policy.blob_ttl must be positive")
	}

	if c.GC.Policy.DiskHighThresholdPercent < 1 || c.GC.Policy.DiskHighThresholdPercent > 99 {
		return errors.New("gc.policy.disk_high_threshold_percent must be within [1, 99]")
	}

	if c.GC.Policy.DiskLowThresholdPercent < 1 || c.GC.Policy.DiskLowThresholdPercent >= c.GC.Policy.DiskHighThresholdPercent {
		return errors.New("gc.policy.disk_low_threshold_percent must be at least 1 and below gc.policy.disk_high_threshold_percent")
	}

	if c.Preheat.MaxConcurrentImages <= 0 {
		return errors.New("preheat.max_concurrent_images must be positive")
	}

	if !filepath.IsAbs(c.Installer.ServiceAccountPath) {
		return fmt.Errorf("installer.service_account_path must be an absolute path, got %q", c.Installer.ServiceAccountPath)
	}

	if c.Installer.SyncInterval <= 0 {
		return errors.New("installer.sync_interval must be positive")
	}

	if c.Installer.Registries.Enable {
		if c.Registry.ConfigPath == "" {
			return errors.New("registry.config_path must not be empty with installer.registries.enable, which installs certs.d there")
		}
	}

	if c.Nydusd.Driver != DriverFUSE {
		return fmt.Errorf("unsupported nydusd.driver %q", c.Nydusd.Driver)
	}

	if !filepath.IsAbs(c.Nydusd.Binary) {
		return fmt.Errorf("nydusd.binary must be an absolute path, got %q", c.Nydusd.Binary)
	}

	if !slices.Contains(nydusdLogLevels, c.Nydusd.Log.Level) {
		return fmt.Errorf("invalid nydusd.log.level %q, want one of %s", c.Nydusd.Log.Level, strings.Join(nydusdLogLevels, ", "))
	}

	if time.Duration(c.Nydusd.MountTimeout) < minMountTimeout {
		return fmt.Errorf("nydusd.mount_timeout must be at least %s", minMountTimeout)
	}

	if c.Nydusd.WatchdogTimeout != 0 {
		if time.Duration(c.Nydusd.WatchdogTimeout) < minWatchdogTimeout {
			return fmt.Errorf("nydusd.watchdog_timeout must be 0 or at least %s", minWatchdogTimeout)
		}
	}

	if !filepath.IsAbs(c.Nydusd.Config.RuntimeDir) {
		return fmt.Errorf("nydusd.config.runtime_dir must be an absolute path, got %q", c.Nydusd.Config.RuntimeDir)
	}

	if c.Nydusd.Config.Backend.Config.HTTP.RequestTimeout <= 0 {
		return errors.New("nydusd.config.backend.config.http.request_timeout must be positive")
	}

	if c.Nydusd.Config.Backend.Config.HTTP.RequestReadTimeout <= 0 {
		return errors.New("nydusd.config.backend.config.http.request_read_timeout must be positive")
	}

	if c.Nydusd.Config.Backend.Config.HTTP.MaxRetries < 0 {
		return errors.New("nydusd.config.backend.config.http.max_retries must not be negative")
	}

	// The address may carry the proxy's credentials, so it is never echoed.
	if c.Nydusd.Config.Backend.Config.HTTP.Proxy.Addr != "" {
		u, err := url.Parse(c.Nydusd.Config.Backend.Config.HTTP.Proxy.Addr)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errors.New("nydusd.config.backend.config.http.proxy.addr must be a URL with a scheme and a host")
		}
	}

	// Dragonfly counts only with a scheduler endpoint.
	if c.Nydusd.Config.Backend.Config.Dragonfly.SchedulerEndpoint != "" {
		if c.Nydusd.Config.Backend.Config.Dragonfly.RequestTimeout <= 0 {
			return errors.New("nydusd.config.backend.config.dragonfly.request_timeout must be positive")
		}

		if c.Nydusd.Config.Backend.Config.Dragonfly.RequestReadTimeout <= 0 {
			return errors.New("nydusd.config.backend.config.dragonfly.request_read_timeout must be positive")
		}

		if c.Nydusd.Config.Backend.Config.Dragonfly.MaxRetries < 0 || c.Nydusd.Config.Backend.Config.Dragonfly.MaxRetries > maxDragonflyRetries {
			return fmt.Errorf("nydusd.config.backend.config.dragonfly.max_retries must be within [0, %d]", maxDragonflyRetries)
		}
	}

	if c.Nydusd.Config.Backend.Config.Fallback.RequestTimeout <= 0 {
		return errors.New("nydusd.config.backend.config.fallback.request_timeout must be positive")
	}

	if c.Nydusd.Config.Backend.Config.Fallback.RequestReadTimeout <= 0 {
		return errors.New("nydusd.config.backend.config.fallback.request_read_timeout must be positive")
	}

	if c.Nydusd.Config.Backend.Config.Fallback.MaxRetries < 0 {
		return errors.New("nydusd.config.backend.config.fallback.max_retries must not be negative")
	}

	if c.Nydusd.Config.Backend.Config.Fallback.RateLimit < 1 {
		return errors.New("nydusd.config.backend.config.fallback.rate_limit must be at least 1")
	}

	if c.Nydusd.Config.Storage.Dir != "" {
		if !filepath.IsAbs(c.Nydusd.Config.Storage.Dir) {
			return fmt.Errorf("nydusd.config.storage.dir must be an absolute path, got %q", c.Nydusd.Config.Storage.Dir)
		}
	}

	if c.Nydusd.Config.Prefetch.ConcurrentBlobCount < 1 {
		return errors.New("nydusd.config.prefetch.concurrent_blob_count must be at least 1")
	}

	if c.Nydusd.Config.Prefetch.RequestTimeout <= 0 {
		return errors.New("nydusd.config.prefetch.request_timeout must be positive")
	}

	if c.Nydusd.Config.Prefetch.RetryInterval < 0 {
		return errors.New("nydusd.config.prefetch.retry_interval must not be negative")
	}

	if !slices.Contains(PrefetchScopes, c.Nydusd.Config.Prefetch.Scope) {
		return fmt.Errorf("invalid nydusd.config.prefetch.scope %q, want one of %s", c.Nydusd.Config.Prefetch.Scope, strings.Join(PrefetchScopes, ", "))
	}

	return nil
}

// Load reads the config at path into c: the file decoded strictly over the
// defaults and validated. A file that does not load leaves c as it was.
func (c *Config) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	cfg := New()
	if err := cfg.Parse(data); err != nil {
		return fmt.Errorf("load config %s: %w", path, err)
	}

	*c = *cfg
	c.path = path

	return nil
}

// Reload reads the file c was loaded from again and returns c with the
// settings of the file that apply without a restart. It reports whether the
// returned config differs from c, and whether the file changes a setting
// that applies on the next restart.
//
//	cgroup, nydusd.config                    ─▶ from the file
//	cgroup.slice, nydusd.config.runtime_dir,
//	nydusd.config.storage.dir                ─▶ c's, the running daemons live there
//	installer                                ─▶ c's, the snapshotter ignores it
//	any other key                            ─▶ c's until the next restart
//
// An empty file is one caught mid-write, not a config, and changes nothing.
func (c *Config) Reload() (cfg *Config, changed, restartOnly bool, err error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, false, false, fmt.Errorf("read config: %w", err)
	}

	if len(data) == 0 {
		return c, false, false, nil
	}

	next := New()
	if err := next.Parse(data); err != nil {
		return nil, false, false, fmt.Errorf("load config %s: %w", c.path, err)
	}
	next.path = c.path
	next.Installer = c.Installer

	reloaded := *c
	reloaded.Cgroup = next.Cgroup
	reloaded.Cgroup.Slice = c.Cgroup.Slice
	reloaded.Nydusd.Config = next.Nydusd.Config
	reloaded.Nydusd.Config.RuntimeDir = c.Nydusd.Config.RuntimeDir
	reloaded.Nydusd.Config.Storage.Dir = c.Nydusd.Config.Storage.Dir

	return &reloaded, !reflect.DeepEqual(&reloaded, c), !reflect.DeepEqual(&reloaded, next), nil
}

// Path returns the file the config was loaded from, empty for a config that
// was not loaded from one.
func (c *Config) Path() string {
	return c.path
}

// DaemonRuntimesDir returns the tmpfs parent of the daemons' runtime
// directories and API sockets.
func (c *Config) DaemonRuntimesDir() string {
	return filepath.Join(c.RuntimeDir, "nydusd")
}

// DaemonInstancesDir returns the persistent parent of the daemons'
// directories.
func (c *Config) DaemonInstancesDir() string {
	return filepath.Join(c.RootDir, "nydusd")
}

// APISocket returns the API socket of a daemon.
func (c *Config) APISocket(id string) string {
	return filepath.Join(c.DaemonRuntimesDir(), id+".sock")
}

// DaemonRuntimeDir returns the tmpfs directory of a daemon.
func (c *Config) DaemonRuntimeDir(id string) string {
	return filepath.Join(c.DaemonRuntimesDir(), id)
}

// DaemonInstanceDir returns the persistent directory of a daemon.
func (c *Config) DaemonInstanceDir(id string) string {
	return filepath.Join(c.DaemonInstancesDir(), id)
}

// PreheatRuntimesDir returns the tmpfs parent of the preheats' directories.
func (c *Config) PreheatRuntimesDir() string {
	return filepath.Join(c.RuntimeDir, "preheat")
}

// PreheatRuntimeDir returns the tmpfs directory of a preheat.
func (c *Config) PreheatRuntimeDir(id string) string {
	return filepath.Join(c.PreheatRuntimesDir(), id)
}

// CacheDir returns the shared blob cache directory.
func (c *Config) CacheDir() string {
	return cmp.Or(c.Nydusd.Config.Storage.Dir, filepath.Join(c.RootDir, "cache"))
}
