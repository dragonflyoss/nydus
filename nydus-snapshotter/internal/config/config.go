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
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	// Version is the config schema version this binary understands.
	Version = 1

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

// DriverFUSE is the FUSE mount driver.
const DriverFUSE = "fuse"

// PrefetchScopes are the prefetch scopes nydusd accepts.
var PrefetchScopes = []string{"none", "ondemand", "all", "auto"}

// nydusdLogLevels are the log levels nydusd accepts.
var nydusdLogLevels = []string{"trace", "debug", "info", "warn", "error"}

// sliceRegexp matches a slice unit name, refer to
// https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html.
var sliceRegexp = regexp.MustCompile(`^[0-9A-Za-z:_\\-][0-9A-Za-z:_.\\-]*\.slice$`)

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
	// Level is the log level, one logrus parses: trace, debug, info, warn or
	// error.
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
	// ConfigPath is the certs.d directory holding <host>/hosts.toml, or a
	// list of them as containerd's config_path is.
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

	// LogLevel is the log level of a daemon: trace, debug, info, warn or
	// error.
	LogLevel string `yaml:"log_level"`

	// LogMaxFiles is the number of log files a daemon keeps.
	LogMaxFiles int `yaml:"log_max_files"`

	// MountTimeout bounds a daemon start, a unit job and a mount wait.
	MountTimeout Duration `yaml:"mount_timeout"`

	// WatchdogTimeout is how long systemd waits for the keep-alive a daemon
	// sends before it takes the daemon for hung and kills it, 0 to disable.
	WatchdogTimeout Duration `yaml:"watchdog_timeout"`

	// PrefetchScope is the default prefetch scope, overridden per image by
	// the nydus-prefetch label.
	PrefetchScope string `yaml:"prefetch_scope"`

	// Dragonfly is copied into backend.config.dragonfly when set.
	Dragonfly NydusdDragonflyConfig `yaml:"dragonfly"`
}

// NydusdDragonflyConfig is the Dragonfly config of a daemon, which mirrors
// nydus-config's backend.config.dragonfly.
type NydusdDragonflyConfig struct {
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

// Load reads, decodes strictly and validates the config at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
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

	// The keys of a second document would be dropped without a word.
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode config: more than one YAML document")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the config, section by section, as containerd validates its
// CRI config, refer to
// https://github.com/containerd/containerd/blob/main/internal/cri/config/config.go.
func (c *Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d, want %d", c.Version, Version)
	}

	if err := c.validatePaths(); err != nil {
		return err
	}

	if _, err := logrus.ParseLevel(c.Log.Level); err != nil {
		return fmt.Errorf("invalid log.level: %w", err)
	}

	if c.Metrics.Address != "" {
		if _, _, err := net.SplitHostPort(c.Metrics.Address); err != nil {
			return fmt.Errorf("invalid metrics.address: %w", err)
		}
	}

	if _, err := labels.Parse(c.Auth.KubeSecret.LabelSelector); err != nil {
		return fmt.Errorf("invalid auth.kube_secret.label_selector: %w", err)
	}

	if err := c.Nydusd.validate(); err != nil {
		return err
	}

	if !sliceRegexp.MatchString(c.Cgroup.Slice) {
		return fmt.Errorf("invalid cgroup.slice %q", c.Cgroup.Slice)
	}

	return c.GC.validate()
}

// validatePaths checks that paths are absolute and that the socket paths fit
// a unix socket address.
func (c *Config) validatePaths() error {
	for _, p := range []struct {
		name, path string
		optional   bool
	}{
		{name: "root", path: c.Root},
		{name: "address", path: c.Address},
		{name: "run_dir", path: c.RunDir},
		{name: "auth.docker_config.path", path: c.Auth.DockerConfig.Path, optional: true},
		{name: "auth.kube_secret.kubeconfig", path: c.Auth.KubeSecret.Kubeconfig, optional: true},
		{name: "nydusd.binary", path: c.Nydusd.Binary},
		{name: "nydusd.template", path: c.Nydusd.Template},
		{name: "nydusd.log_dir", path: c.Nydusd.LogDir},
	} {
		if p.optional && p.path == "" {
			continue
		}

		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s must be an absolute path, got %q", p.name, p.path)
		}
	}

	for _, path := range filepath.SplitList(c.Registry.ConfigPath) {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("registry.config_path must hold absolute paths, got %q", c.Registry.ConfigPath)
		}
	}

	if len(c.Address) > maxSocketPath {
		return fmt.Errorf("address %q is %d bytes long, over the %d byte limit", c.Address, len(c.Address), maxSocketPath)
	}

	if socket := c.APISocket(strings.Repeat("0", daemonIDLength)); len(socket) > maxSocketPath {
		return fmt.Errorf("run_dir %q makes the daemon API socket %d bytes long, over the %d byte limit", c.RunDir, len(socket), maxSocketPath)
	}

	return nil
}

// validate checks the daemon config.
func (n *NydusdConfig) validate() error {
	if n.Driver != DriverFUSE {
		return fmt.Errorf("unsupported nydusd.driver %q", n.Driver)
	}

	if !slices.Contains(nydusdLogLevels, n.LogLevel) {
		return fmt.Errorf("invalid nydusd.log_level %q, want one of %s", n.LogLevel, strings.Join(nydusdLogLevels, ", "))
	}

	if n.LogMaxFiles < 1 {
		return errors.New("nydusd.log_max_files must be at least 1")
	}

	if time.Duration(n.MountTimeout) < minMountTimeout {
		return fmt.Errorf("nydusd.mount_timeout must be at least %s", minMountTimeout)
	}

	if timeout := time.Duration(n.WatchdogTimeout); timeout != 0 && timeout < minWatchdogTimeout {
		return fmt.Errorf("nydusd.watchdog_timeout must be 0 or at least %s", minWatchdogTimeout)
	}

	if !slices.Contains(PrefetchScopes, n.PrefetchScope) {
		return fmt.Errorf("invalid nydusd.prefetch_scope %q, want one of %s", n.PrefetchScope, strings.Join(PrefetchScopes, ", "))
	}

	return n.Dragonfly.validate()
}

// validate checks the Dragonfly config, which counts only with a scheduler
// endpoint.
func (d *NydusdDragonflyConfig) validate() error {
	if d.SchedulerEndpoint == "" {
		return nil
	}

	if d.RequestTimeout <= 0 {
		return errors.New("nydusd.dragonfly.request_timeout must be positive")
	}

	if d.MaxRetries < 0 || d.MaxRetries > maxDragonflyRetries {
		return fmt.Errorf("nydusd.dragonfly.max_retries must be within [0, %d]", maxDragonflyRetries)
	}

	if d.FallbackRateLimit < 1 {
		return errors.New("nydusd.dragonfly.fallback_rate_limit must be at least 1")
	}

	return nil
}

// validate checks the blob cache GC config.
func (g *GCConfig) validate() error {
	if g.Interval <= 0 {
		return errors.New("gc.interval must be positive")
	}

	if g.Policy.BlobTTL <= 0 {
		return errors.New("gc.policy.blob_ttl must be positive")
	}

	if low, high := g.Policy.DiskLowThresholdPercent, g.Policy.DiskHighThresholdPercent; high < 1 || high > 99 || low < 1 || low >= high {
		return fmt.Errorf("invalid gc.policy thresholds: low %d%%, high %d%%", low, high)
	}

	return nil
}

// Merge returns the running config with the settings of next that apply
// without a restart: the cgroup limits and the dragonfly section. It reports
// whether next changes anything else, which applies on the next restart; a
// new cgroup slice would hide the running daemons, so it is one of those.
func (c *Config) Merge(next *Config) (*Config, bool) {
	merged := *c
	merged.Cgroup = next.Cgroup
	merged.Cgroup.Slice = c.Cgroup.Slice
	merged.Nydusd.Dragonfly = next.Nydusd.Dragonfly

	return &merged, !reflect.DeepEqual(&merged, next)
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
