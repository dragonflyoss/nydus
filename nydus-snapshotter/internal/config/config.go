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
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
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

	// Config is the config of each daemon.
	Config NydusdDaemonConfig `yaml:"config"`
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
	if err := c.validatePaths(); err != nil {
		return err
	}

	if _, err := logrus.ParseLevel(c.Log.Level); err != nil {
		return fmt.Errorf("invalid log.level: %w", err)
	}

	if c.Metrics.Addr != "" {
		if _, _, err := net.SplitHostPort(c.Metrics.Addr); err != nil {
			return fmt.Errorf("invalid metrics.addr: %w", err)
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
		{name: "root_dir", path: c.RootDir},
		{name: "runtime_dir", path: c.RuntimeDir},
		{name: "grpc.addr", path: c.GRPC.Addr},
		{name: "auth.docker_config.path", path: c.Auth.DockerConfig.Path, optional: true},
		{name: "auth.kube_secret.kubeconfig", path: c.Auth.KubeSecret.Kubeconfig, optional: true},
		{name: "nydusd.binary", path: c.Nydusd.Binary},
		{name: "nydusd.log_dir", path: c.Nydusd.LogDir},
		{name: "nydusd.config.runtime_dir", path: c.Nydusd.Config.RuntimeDir},
		{name: "nydusd.config.storage.dir", path: c.Nydusd.Config.Storage.Dir, optional: true},
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

	if len(c.GRPC.Addr) > maxSocketPath {
		return fmt.Errorf("grpc.addr %q is %d bytes long, over the %d byte limit", c.GRPC.Addr, len(c.GRPC.Addr), maxSocketPath)
	}

	if socket := c.APISocket(strings.Repeat("0", daemonIDLength)); len(socket) > maxSocketPath {
		return fmt.Errorf("runtime_dir %q makes the daemon API socket %d bytes long, over the %d byte limit", c.RuntimeDir, len(socket), maxSocketPath)
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

	if err := n.Config.Backend.Config.validate(); err != nil {
		return err
	}

	return n.Config.Prefetch.validate()
}

// validate checks the prefetch config.
func (p *NydusdPrefetchConfig) validate() error {
	if p.ConcurrentBlobCount < 1 {
		return errors.New("nydusd.config.prefetch.concurrent_blob_count must be at least 1")
	}

	if p.RequestTimeout <= 0 {
		return errors.New("nydusd.config.prefetch.request_timeout must be positive")
	}

	if p.RetryInterval < 0 {
		return errors.New("nydusd.config.prefetch.retry_interval must not be negative")
	}

	if !slices.Contains(PrefetchScopes, p.Scope) {
		return fmt.Errorf("invalid nydusd.config.prefetch.scope %q, want one of %s", p.Scope, strings.Join(PrefetchScopes, ", "))
	}

	return nil
}

// validate checks the registry backend config.
func (r *NydusdRegistryConfig) validate() error {
	for _, c := range []struct {
		name                               string
		requestTimeout, requestReadTimeout Duration
		maxRetries                         int
	}{
		{name: "http", requestTimeout: r.HTTP.RequestTimeout, requestReadTimeout: r.HTTP.RequestReadTimeout, maxRetries: r.HTTP.MaxRetries},
		{name: "fallback", requestTimeout: r.Fallback.RequestTimeout, requestReadTimeout: r.Fallback.RequestReadTimeout, maxRetries: r.Fallback.MaxRetries},
	} {
		if c.requestTimeout <= 0 {
			return fmt.Errorf("nydusd.config.backend.config.%s.request_timeout must be positive", c.name)
		}

		if c.requestReadTimeout <= 0 {
			return fmt.Errorf("nydusd.config.backend.config.%s.request_read_timeout must be positive", c.name)
		}

		if c.maxRetries < 0 {
			return fmt.Errorf("nydusd.config.backend.config.%s.max_retries must not be negative", c.name)
		}
	}

	if r.Fallback.RateLimit < 1 {
		return errors.New("nydusd.config.backend.config.fallback.rate_limit must be at least 1")
	}

	// The address may carry the proxy's credentials, so it is never echoed.
	if addr := r.HTTP.Proxy.Addr; addr != "" {
		if u, err := url.Parse(addr); err != nil || u.Scheme == "" || u.Host == "" {
			return errors.New("nydusd.config.backend.config.http.proxy.addr must be a URL with a scheme and a host")
		}
	}

	return r.Dragonfly.validate()
}

// validate checks the Dragonfly config, which counts only with a scheduler
// endpoint.
func (d *NydusdDragonflyConfig) validate() error {
	if d.SchedulerEndpoint == "" {
		return nil
	}

	if d.RequestTimeout <= 0 {
		return errors.New("nydusd.config.backend.config.dragonfly.request_timeout must be positive")
	}

	if d.RequestReadTimeout <= 0 {
		return errors.New("nydusd.config.backend.config.dragonfly.request_read_timeout must be positive")
	}

	if d.MaxRetries < 0 || d.MaxRetries > maxDragonflyRetries {
		return fmt.Errorf("nydusd.config.backend.config.dragonfly.max_retries must be within [0, %d]", maxDragonflyRetries)
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
// without a restart: the cgroup limits and nydusd.config, which a daemon
// reads when it starts. It reports whether next changes anything else, which
// applies on the next restart; a new cgroup slice, runtime directory or cache
// directory would hide the running daemons' own, so they are among those.
func (c *Config) Merge(next *Config) (*Config, bool) {
	merged := *c
	merged.Cgroup = next.Cgroup
	merged.Cgroup.Slice = c.Cgroup.Slice
	merged.Nydusd.Config = next.Nydusd.Config
	merged.Nydusd.Config.RuntimeDir = c.Nydusd.Config.RuntimeDir
	merged.Nydusd.Config.Storage.Dir = c.Nydusd.Config.Storage.Dir

	return &merged, !reflect.DeepEqual(&merged, next)
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

// CacheDir returns the shared blob cache directory.
func (c *Config) CacheDir() string {
	return cmp.Or(c.Nydusd.Config.Storage.Dir, filepath.Join(c.RootDir, "cache"))
}
