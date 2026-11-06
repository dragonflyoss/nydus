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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/containerd/log"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// Version is the config schema version this binary understands.
	Version = 1

	// DefaultPath is the default config file path.
	DefaultPath = "/etc/nydus-v3/config.yaml"

	// DefaultRoot is the default root directory of snapshots, the cache and
	// daemon instances.
	DefaultRoot = "/var/lib/containerd-nydus-v3"

	// DefaultAddress is the default gRPC socket containerd connects to.
	DefaultAddress = "/run/containerd-nydus-v3/containerd-nydus-grpc.sock"

	// DefaultRunDir is the tmpfs directory holding daemon API sockets and
	// rendered configs, which carry credentials and must not reach disk.
	DefaultRunDir = "/run/containerd-nydus-v3"

	// DefaultLogLevel is the default log level.
	DefaultLogLevel = "info"

	// DefaultMetricsAddress is the default metrics and health address.
	DefaultMetricsAddress = "127.0.0.1:4010"

	// DefaultRegistryConfigPath is the default certs.d directory.
	DefaultRegistryConfigPath = "/etc/nydus-v3/certs.d"

	// DefaultKubeconfig is the kubeconfig the installer keeps in sync. It
	// names the service account token, so it lives on tmpfs.
	DefaultKubeconfig = "/run/containerd-nydus-v3/kubernetes/kubeconfig"

	// DefaultNydusdBinary is the nydus binary the installer points at the
	// current version.
	DefaultNydusdBinary = "/opt/nydus-v3/bin/current/nydus"

	// DefaultNydusdTemplate is the default nydusd config template.
	DefaultNydusdTemplate = "/etc/nydus-v3/nydusd.template.yaml"

	// DefaultNydusdLogDir is the default parent of per-daemon log dirs.
	DefaultNydusdLogDir = "/var/log/nydus-v3/nydusd"

	// DefaultPrefetchScope is the default prefetch scope of a daemon.
	DefaultPrefetchScope = "auto"

	// DefaultMountTimeout bounds a daemon start, a unit job and a mount wait.
	DefaultMountTimeout = Duration(10 * time.Second)

	// DefaultSlice is the slice daemons run in.
	DefaultSlice = "system-nydus-v3.slice"

	// DefaultDragonflyRequestTimeout is nydus's default timeout of a request
	// through seed peers, refer to the Dragonfly section of docs/nydus.md.
	DefaultDragonflyRequestTimeout = Duration(5 * time.Second)

	// DefaultDragonflyMaxRetries is nydus's default retry count of an
	// on-demand read through seed peers.
	DefaultDragonflyMaxRetries = 1

	// DefaultDragonflyFallbackRateLimit is nydus's default origin fallback
	// rate in requests per second.
	DefaultDragonflyFallbackRateLimit = 1

	// DefaultGCInterval is the default cache GC interval, as dfdaemon's.
	DefaultGCInterval = Duration(15 * time.Minute)

	// DefaultBlobTTL is the default cache TTL of an unused blob.
	DefaultBlobTTL = Duration(30 * 24 * time.Hour)

	// DefaultDiskHighThresholdPercent starts disk watermark eviction.
	DefaultDiskHighThresholdPercent = 80

	// DefaultDiskLowThresholdPercent stops disk watermark eviction.
	DefaultDiskLowThresholdPercent = 60

	// maxSocketPath is the length limit of a unix socket path (sun_path).
	maxSocketPath = 107

	// daemonIDLength is the length of a daemon ID, the hex of a sha256 chain
	// ID.
	daemonIDLength = 64

	// maxDragonflyRetries is the retry limit nydus accepts for Dragonfly
	// reads, refer to the Registry backend section of docs/nydus.md.
	maxDragonflyRetries = 3
)

// DriverFuse is the FUSE mount driver.
const DriverFuse = "fuse"

// PrefetchScopes are the prefetch scopes nydusd accepts.
var PrefetchScopes = []string{"none", "ondemand", "all", "auto"}

// Config is the snapshotter config.
type Config struct {
	// Version is the schema version, refer to containerd's config version.
	Version int `yaml:"version"`

	// Root is the root directory of snapshots, the cache and instances.
	Root string `yaml:"root"`

	// Address is the gRPC socket path containerd connects to.
	Address string `yaml:"address"`

	// RunDir holds daemon API sockets and rendered configs on tmpfs.
	RunDir string `yaml:"run_dir"`

	// Log is the logging config.
	Log LogConfig `yaml:"log"`

	// Metrics is the metrics and health server config.
	Metrics MetricsConfig `yaml:"metrics"`

	// Registry is the registry host config.
	Registry RegistryConfig `yaml:"registry"`

	// Auth is the registry credential config.
	Auth AuthConfig `yaml:"auth"`

	// Nydusd is the daemon config.
	Nydusd NydusdConfig `yaml:"nydusd"`

	// Cgroup is the daemon resource config.
	Cgroup CgroupConfig `yaml:"cgroup"`

	// GC is the blob cache GC config.
	GC GCConfig `yaml:"gc"`
}

// LogConfig is the logging config.
type LogConfig struct {
	// Level is the log level: trace, debug, info, warn or error.
	Level string `yaml:"level"`
}

// MetricsConfig is the metrics and health server config.
type MetricsConfig struct {
	// Address is the listen address of /metrics, /livez and /readyz, empty to
	// disable.
	Address string `yaml:"address"`
}

// RegistryConfig is the registry host config.
type RegistryConfig struct {
	// ConfigPath is the certs.d directory holding <host>/hosts.toml.
	ConfigPath string `yaml:"config_path"`
}

// AuthConfig is the registry credential config.
type AuthConfig struct {
	// DockerConfig is the docker config.json source, always on.
	DockerConfig DockerConfigAuthConfig `yaml:"docker_config"`

	// KubeSecret is the Kubernetes secret source, optional.
	KubeSecret KubeSecretAuthConfig `yaml:"kubesecret"`
}

// DockerConfigAuthConfig is the docker config.json source.
type DockerConfigAuthConfig struct {
	// Path is the config.json path, empty for kubelet's search order.
	Path string `yaml:"path"`
}

// KubeSecretAuthConfig is the Kubernetes secret source.
type KubeSecretAuthConfig struct {
	// Enable turns on the secret informer.
	Enable bool `yaml:"enable"`

	// Kubeconfig is the kubeconfig path, empty for in-cluster config.
	Kubeconfig string `yaml:"kubeconfig"`

	// LabelSelector narrows the watched secrets.
	LabelSelector string `yaml:"label_selector"`
}

// NydusdConfig is the daemon config.
type NydusdConfig struct {
	// Driver is the mount driver, only fuse today.
	Driver string `yaml:"driver"`

	// Binary is the nydus binary; symlinks are resolved when a daemon starts
	// so an upgrade never changes a running unit.
	Binary string `yaml:"binary"`

	// Template is the nydus-config YAML shared by all daemons.
	Template string `yaml:"template"`

	// LogDir is the parent of per-daemon log dirs.
	LogDir string `yaml:"log_dir"`

	// MountTimeout bounds a daemon start, a unit job and a mount wait.
	MountTimeout Duration `yaml:"mount_timeout"`

	// PrefetchScope is the default prefetch scope, overridden per image by
	// the nydus-prefetch label.
	PrefetchScope string `yaml:"prefetch_scope"`

	// Dragonfly is copied into backend.config.dragonfly when set.
	Dragonfly DragonflyConfig `yaml:"dragonfly"`
}

// DragonflyConfig mirrors nydus-config's backend.config.dragonfly.
type DragonflyConfig struct {
	// SchedulerEndpoint is the Dragonfly scheduler address, empty to disable.
	SchedulerEndpoint string `yaml:"scheduler_endpoint"`

	// RequestTimeout is the timeout of each request through seed peers.
	RequestTimeout Duration `yaml:"request_timeout"`

	// MaxRetries is the retry count of an on-demand read; 0 is rendered, so
	// it never falls back to nydus's default.
	MaxRetries int `yaml:"max_retries"`

	// FallbackRateLimit is the origin fallback rate in requests per second.
	FallbackRateLimit int `yaml:"fallback_rate_limit"`
}

// CgroupConfig is the daemon resource config.
type CgroupConfig struct {
	// Slice is the slice daemons run in; its parent holds the total budget.
	Slice string `yaml:"slice"`

	// MemoryMax is the total memory.max of all daemons, 0 for no limit.
	MemoryMax Size `yaml:"memory_max"`

	// MemoryHigh is the total memory.high of all daemons, 0 for no limit.
	MemoryHigh Size `yaml:"memory_high"`

	// CPUQuota is the total CPU quota of all daemons, 0 for no limit.
	CPUQuota Percent `yaml:"cpu_quota"`

	// Daemon is the per-daemon budget.
	Daemon DaemonCgroupConfig `yaml:"daemon"`
}

// ParentSlice returns the slice holding the total budget, the parent of the
// daemon slice: every "-" in a slice name is a nesting level, refer to
// systemd.slice(5). A top level daemon slice holds the total itself.
func (c *CgroupConfig) ParentSlice() string {
	name := strings.TrimSuffix(c.Slice, ".slice")
	i := strings.LastIndex(name, "-")
	if i <= 0 {
		return c.Slice
	}

	return name[:i] + ".slice"
}

// DaemonCgroupConfig is the per-daemon resource config.
type DaemonCgroupConfig struct {
	// MemoryHigh is the per-daemon memory.high, 0 for no limit.
	MemoryHigh Size `yaml:"memory_high"`

	// CPUQuota is the per-daemon CPU quota, 0 for no limit.
	CPUQuota Percent `yaml:"cpu_quota"`
}

// GCConfig is the blob cache GC config, refer to dfdaemon's gc config.
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
			KubeSecret: KubeSecretAuthConfig{
				Kubeconfig: DefaultKubeconfig,
			},
		},
		Nydusd: NydusdConfig{
			Driver:        DriverFuse,
			Binary:        DefaultNydusdBinary,
			Template:      DefaultNydusdTemplate,
			LogDir:        DefaultNydusdLogDir,
			MountTimeout:  DefaultMountTimeout,
			PrefetchScope: DefaultPrefetchScope,
			Dragonfly: DragonflyConfig{
				RequestTimeout:    DefaultDragonflyRequestTimeout,
				MaxRetries:        DefaultDragonflyMaxRetries,
				FallbackRateLimit: DefaultDragonflyFallbackRateLimit,
			},
		},
		Cgroup: CgroupConfig{
			Slice: DefaultSlice,
		},
		GC: GCConfig{
			Interval: DefaultGCInterval,
			Policy: GCPolicyConfig{
				BlobTTL:                  DefaultBlobTTL,
				DiskHighThresholdPercent: DefaultDiskHighThresholdPercent,
				DiskLowThresholdPercent:  DefaultDiskLowThresholdPercent,
			},
		},
	}
}

// Load reads, decodes strictly and validates the config at path. A missing
// file yields the defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		log.L.WithField("path", path).Warn("config not found, using defaults")
	} else if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}

	return cfg, nil
}

// Parse decodes strictly and validates a YAML config over the defaults. An
// empty document keeps the defaults.
func Parse(data []byte) (*Config, error) {
	cfg := New()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the config.
func (c *Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d, want %d", c.Version, Version)
	}

	for _, p := range []struct{ name, path string }{
		{name: "root", path: c.Root},
		{name: "address", path: c.Address},
		{name: "run_dir", path: c.RunDir},
		{name: "nydusd.binary", path: c.Nydusd.Binary},
		{name: "nydusd.template", path: c.Nydusd.Template},
		{name: "nydusd.log_dir", path: c.Nydusd.LogDir},
	} {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s must be an absolute path, got %q", p.name, p.path)
		}
	}

	if _, err := logrus.ParseLevel(c.Log.Level); err != nil {
		return fmt.Errorf("invalid log.level: %w", err)
	}

	if c.Nydusd.Driver != DriverFuse {
		return fmt.Errorf("unsupported nydusd.driver %q", c.Nydusd.Driver)
	}

	if !slices.Contains(PrefetchScopes, c.Nydusd.PrefetchScope) {
		return fmt.Errorf("invalid nydusd.prefetch_scope %q, want one of %s", c.Nydusd.PrefetchScope, strings.Join(PrefetchScopes, ", "))
	}

	if c.Nydusd.MountTimeout <= 0 {
		return errors.New("nydusd.mount_timeout must be positive")
	}

	if !strings.HasSuffix(c.Cgroup.Slice, ".slice") {
		return fmt.Errorf("invalid cgroup.slice %q", c.Cgroup.Slice)
	}

	if err := c.validateOptionalPaths(); err != nil {
		return err
	}

	if _, err := labels.Parse(c.Auth.KubeSecret.LabelSelector); err != nil {
		return fmt.Errorf("invalid auth.kubesecret.label_selector: %w", err)
	}

	if dragonfly := c.Nydusd.Dragonfly; dragonfly.SchedulerEndpoint != "" {
		if dragonfly.RequestTimeout <= 0 {
			return errors.New("nydusd.dragonfly.request_timeout must be positive")
		}

		if dragonfly.MaxRetries < 0 || dragonfly.MaxRetries > maxDragonflyRetries {
			return fmt.Errorf("nydusd.dragonfly.max_retries must be within [0, %d]", maxDragonflyRetries)
		}

		if dragonfly.FallbackRateLimit < 1 {
			return errors.New("nydusd.dragonfly.fallback_rate_limit must be at least 1")
		}
	}

	if c.GC.Interval <= 0 {
		return errors.New("gc.interval must be positive")
	}

	if c.GC.Policy.BlobTTL <= 0 {
		return errors.New("gc.policy.blob_ttl must be positive")
	}

	if policy := c.GC.Policy; policy.DiskHighThresholdPercent < 1 || policy.DiskHighThresholdPercent > 99 ||
		policy.DiskLowThresholdPercent < 1 || policy.DiskLowThresholdPercent >= policy.DiskHighThresholdPercent {
		return fmt.Errorf("invalid gc.policy thresholds: low %d%%, high %d%%", policy.DiskLowThresholdPercent, policy.DiskHighThresholdPercent)
	}

	// The daemon API socket path must fit sun_path.
	if socket := c.APISocket(strings.Repeat("0", daemonIDLength)); len(socket) > maxSocketPath {
		return fmt.Errorf("run_dir %q makes the daemon API socket %d bytes long, over the %d byte limit", c.RunDir, len(socket), maxSocketPath)
	}

	return nil
}

// validateOptionalPaths checks the paths that may be empty are absolute when
// set.
func (c *Config) validateOptionalPaths() error {
	for _, p := range []struct{ name, path string }{
		{name: "registry.config_path", path: c.Registry.ConfigPath},
		{name: "auth.docker_config.path", path: c.Auth.DockerConfig.Path},
		{name: "auth.kubesecret.kubeconfig", path: c.Auth.KubeSecret.Kubeconfig},
	} {
		if p.path != "" && !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s must be an absolute path, got %q", p.name, p.path)
		}
	}

	return nil
}

// RuntimesDir returns the tmpfs parent of the daemons' runtime directories
// and API sockets.
func (c *Config) RuntimesDir() string {
	return filepath.Join(c.RunDir, "nydusd")
}

// InstancesDir returns the persistent parent of the daemons' directories.
func (c *Config) InstancesDir() string {
	return filepath.Join(c.Root, "nydusd")
}

// APISocket returns the API socket of a daemon.
func (c *Config) APISocket(id string) string {
	return filepath.Join(c.RuntimesDir(), id+".sock")
}

// RuntimeDir returns the tmpfs directory of a daemon.
func (c *Config) RuntimeDir(id string) string {
	return filepath.Join(c.RuntimesDir(), id)
}

// InstanceDir returns the persistent directory of a daemon.
func (c *Config) InstanceDir(id string) string {
	return filepath.Join(c.InstancesDir(), id)
}

// CacheDir returns the shared blob cache directory.
func (c *Config) CacheDir() string {
	return filepath.Join(c.Root, "cache")
}
