package mount

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Config mirrors the nydus storage config (nydus-config). It is written as
// JSON, which serde_yaml reads as YAML, so no YAML library is needed. Only
// the fields the tests set are modelled; zero values are omitted and take
// the daemon's defaults.
type Config struct {
	Backend  Backend         `json:"backend"`
	Storage  *StorageConfig  `json:"storage,omitempty"`
	Prefetch *PrefetchConfig `json:"prefetch,omitempty"`
}

// Backend selects the blob backend: Local or Registry.
type Backend struct {
	Type   string `json:"type"`
	Config any    `json:"config"`
}

// RegistryConfig is the registry backend's config.
type RegistryConfig struct {
	Addr       string           `json:"addr"`
	Repository string           `json:"repository"`
	Auth       string           `json:"auth,omitempty"`
	HTTP       *HTTPConfig      `json:"http,omitempty"`
	Dragonfly  *DragonflyConfig `json:"dragonfly,omitempty"`
}

// HTTPConfig is the registry backend's HTTP client config.
type HTTPConfig struct {
	RequestTimeout string       `json:"request_timeout,omitempty"`
	MaxRetries     *int         `json:"max_retries,omitempty"`
	Proxy          *ProxyConfig `json:"proxy,omitempty"`
	TLS            *TLSConfig   `json:"tls,omitempty"`
}

// TLSConfig is the registry backend's TLS trust config.
type TLSConfig struct {
	SkipVerify bool   `json:"skip_verify,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
}

// ProxyConfig is an HTTP forward proxy.
type ProxyConfig struct {
	Addr string `json:"addr"`
}

// DragonflyConfig routes registry reads through the Dragonfly SDK.
type DragonflyConfig struct {
	SchedulerEndpoint string `json:"scheduler_endpoint"`
	RequestTimeout    string `json:"request_timeout,omitempty"`
	MaxRetries        *int   `json:"max_retries,omitempty"`
	FallbackRateLimit *int   `json:"fallback_rate_limit,omitempty"`
}

// RegistryBackend serves blobs from an OCI registry.
func RegistryBackend(r RegistryConfig) Backend {
	return Backend{Type: "registry", Config: r}
}

// StorageConfig is where decoded chunk groups are cached.
type StorageConfig struct {
	Dir                 string `json:"dir,omitempty"`
	SkipVerifyChecksums *bool  `json:"skip_verify_checksums,omitempty"`
	FetchSize           *int64 `json:"fetch_size,omitempty"`
}

// PrefetchConfig controls background prefetch.
type PrefetchConfig struct {
	Scope         string `json:"scope,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
}

// LocalConfig is the config most tests use: a local backend, a persistent
// cache under cacheDir and no prefetch, so every byte a test reads is
// fetched on demand.
func LocalConfig(blobDir, cacheDir string) Config {
	return Config{
		Backend:  Backend{Type: "local", Config: map[string]string{"dir": blobDir}},
		Storage:  &StorageConfig{Dir: cacheDir},
		Prefetch: &PrefetchConfig{Scope: "none"},
	}
}

// Write stores c under dir as name and returns its path.
func (c Config) Write(t testing.TB, dir, name string) string {
	t.Helper()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	return path
}

// Ptr returns a pointer to v, for the optional config fields.
func Ptr[T any](v T) *T { return &v }
