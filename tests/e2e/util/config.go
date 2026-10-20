package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// Config is the nydus daemon config, the YAML `--config` names, with the
// keys the e2e suite sets.
type Config struct {
	// Backend is the blob backend.
	Backend BackendConfig `yaml:"backend"`

	// Storage is the chunk cache.
	Storage StorageConfig `yaml:"storage"`

	// Prefetch is the background blob prefetch.
	Prefetch PrefetchConfig `yaml:"prefetch"`
}

// BackendConfig is the blob backend, `local` or `registry`, with the
// settings of the one type in use.
type BackendConfig struct {
	// Type is the backend type.
	Type string `yaml:"type"`

	// Config is the settings of the backend type.
	Config BackendSettings `yaml:"config"`
}

// BackendSettings is the settings of a backend: Dir for a local backend,
// the rest for a registry backend.
type BackendSettings struct {
	// Dir holds the full blobs of a local backend.
	Dir string `yaml:"dir,omitempty"`

	// Addr is the registry URL, scheme included.
	Addr string `yaml:"addr,omitempty"`

	// Repository is the repository the blobs live in.
	Repository string `yaml:"repository,omitempty"`

	// Auth is the Basic credential, the base64 of user:password.
	Auth string `yaml:"auth,omitempty"`

	// HTTP is the client of requests to the registry, the reads Dragonfly
	// falls back to the origin with included.
	HTTP *HTTPConfig `yaml:"http,omitempty"`

	// Dragonfly routes blob GETs through the Dragonfly seed peers.
	Dragonfly *DragonflyConfig `yaml:"dragonfly,omitempty"`
}

// HTTPConfig is the HTTP client of requests to the registry.
type HTTPConfig struct {
	// RequestTimeout bounds one request.
	RequestTimeout string `yaml:"request_timeout"`

	// MaxRetries is how often a 429, 5xx or 408 is retried at once.
	MaxRetries int `yaml:"max_retries"`

	// Proxy routes every request through an HTTP proxy.
	Proxy *ProxyConfig `yaml:"proxy,omitempty"`

	// TLS is the TLS trust of connections to the registry.
	TLS *TLSConfig `yaml:"tls,omitempty"`
}

// ProxyConfig is an HTTP forward proxy.
type ProxyConfig struct {
	// Addr is the proxy URL, scheme included.
	Addr string `yaml:"addr"`
}

// TLSConfig is the TLS trust of connections to the registry.
type TLSConfig struct {
	// SkipVerify accepts any server certificate.
	SkipVerify bool `yaml:"skip_verify,omitempty"`

	// CACert is a PEM file of certificates to trust besides the system's.
	CACert string `yaml:"ca_cert,omitempty"`
}

// DragonflyConfig routes blob GETs through the Dragonfly seed peers.
type DragonflyConfig struct {
	// SchedulerEndpoint is the Dragonfly scheduler URL.
	SchedulerEndpoint string `yaml:"scheduler_endpoint"`

	// RequestTimeout bounds one request to a seed peer.
	RequestTimeout string `yaml:"request_timeout"`

	// MaxRetries is how many seed peers an on-demand read tries before it
	// goes back to the origin.
	MaxRetries int `yaml:"max_retries"`

	// FallbackRateLimit is the origin requests per second the reads the
	// seed peers cannot serve are allowed, through the registry's HTTP.
	FallbackRateLimit int `yaml:"fallback_rate_limit"`
}

// StorageConfig is the chunk cache.
type StorageConfig struct {
	// Dir holds the cache files.
	Dir string `yaml:"dir"`

	// SkipVerifyChecksums leaves decoded chunk groups unchecked against
	// their crc32c; nil keeps the daemon's default, which checks them.
	SkipVerifyChecksums *bool `yaml:"skip_verify_checksums,omitempty"`
}

// PrefetchConfig is the background blob prefetch.
type PrefetchConfig struct {
	// Scope is `none`, `ondemand`, `all` or `auto`.
	Scope string `yaml:"scope"`

	// RetryInterval is the interval before a prefetch read the backend
	// answered with 429, 5xx or 408 is sent once more, drawn at random
	// between it and twice it, the daemon's 6 to 12 hours by default.
	RetryInterval string `yaml:"retry_interval,omitempty"`
}

// NewLocalBackendConfig returns the config of a local backend over blobDir
// with the cache under cacheDir and the given prefetch scope.
func NewLocalBackendConfig(blobDir, cacheDir, prefetchScope string) Config {
	return Config{
		Backend:  BackendConfig{Type: "local", Config: BackendSettings{Dir: blobDir}},
		Storage:  StorageConfig{Dir: cacheDir},
		Prefetch: PrefetchConfig{Scope: prefetchScope},
	}
}

// NewRegistryBackendConfig returns the config of a registry backend for the
// repository at addr, a URL with its scheme, with the cache under cacheDir,
// a 5s request timeout, 3 retries and prefetch off.
func NewRegistryBackendConfig(addr, repository, cacheDir string) Config {
	return Config{
		Backend: BackendConfig{Type: "registry", Config: BackendSettings{
			Addr:       addr,
			Repository: repository,
			HTTP:       &HTTPConfig{RequestTimeout: "5s", MaxRetries: 3},
		}},
		Storage:  StorageConfig{Dir: cacheDir},
		Prefetch: PrefetchConfig{Scope: "none"},
	}
}

// Write writes the config to path and creates the cache directory.
func (c Config) Write(t *testing.T, path string) {
	t.Helper()
	assert.NoError(t, os.MkdirAll(c.Storage.Dir, 0o755))

	data, err := yaml.Marshal(c)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(path, data, 0o644))
}

// WriteLocalBackendConfig writes the config of a local backend over blobDir
// with the cache under cacheDir and the given prefetch scope to path.
func WriteLocalBackendConfig(t *testing.T, path, blobDir, cacheDir, prefetchScope string) {
	t.Helper()
	NewLocalBackendConfig(blobDir, cacheDir, prefetchScope).Write(t, path)
}
