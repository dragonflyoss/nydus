package mount

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
)

// Config mirrors the nydus storage config (nydus-config). It is written as
// JSON, which serde_yaml reads as YAML, so no YAML library is needed. Only
// the fields the tests set are modelled; zero values are omitted and take
// the daemon's defaults.
type Config struct {
	Backend  Backend   `json:"backend"`
	Storage  *Storage  `json:"storage,omitempty"`
	Prefetch *Prefetch `json:"prefetch,omitempty"`
}

// Backend selects the blob backend: Local or Registry.
type Backend struct {
	Type   string `json:"type"`
	Config any    `json:"config"`
}

// LocalBackend serves blobs from a directory.
func LocalBackend(dir string) Backend {
	return Backend{Type: "local", Config: map[string]string{"dir": dir}}
}

// Registry is the registry backend's config.
type Registry struct {
	Addr       string     `json:"addr"`
	Repository string     `json:"repository"`
	Auth       string     `json:"auth,omitempty"`
	HTTP       *HTTP      `json:"http,omitempty"`
	Dragonfly  *Dragonfly `json:"dragonfly,omitempty"`
}

// HTTP is the registry backend's HTTP client config.
type HTTP struct {
	RequestTimeout string `json:"request_timeout,omitempty"`
	MaxRetries     *int   `json:"max_retries,omitempty"`
	Proxy          *Proxy `json:"proxy,omitempty"`
	TLS            *TLS   `json:"tls,omitempty"`
}

type TLS struct {
	SkipVerify bool   `json:"skip_verify,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`
}

// Proxy is an HTTP forward proxy.
type Proxy struct {
	Addr string `json:"addr"`
}

// Dragonfly routes registry reads through the Dragonfly SDK.
type Dragonfly struct {
	SchedulerEndpoint string `json:"scheduler_endpoint"`
	RequestTimeout    string `json:"request_timeout,omitempty"`
	MaxRetries        *int   `json:"max_retries,omitempty"`
	FallbackRateLimit *int   `json:"fallback_rate_limit,omitempty"`
}

// RegistryBackend serves blobs from an OCI registry.
func RegistryBackend(r Registry) Backend {
	return Backend{Type: "registry", Config: r}
}

// Storage is where decoded chunk groups are cached.
type Storage struct {
	Dir                 string `json:"dir,omitempty"`
	SkipVerifyChecksums *bool  `json:"skip_verify_checksums,omitempty"`
	FetchSize           *int64 `json:"fetch_size,omitempty"`
}

// Prefetch controls background prefetch.
type Prefetch struct {
	Scope         string `json:"scope,omitempty"`
	RetryInterval string `json:"retry_interval,omitempty"`
}

// LocalConfig is the config most tests use: a local backend, a persistent
// cache under cacheDir and no prefetch, so every byte a test reads is
// fetched on demand.
func LocalConfig(blobDir, cacheDir string) Config {
	return Config{
		Backend:  LocalBackend(blobDir),
		Storage:  &Storage{Dir: cacheDir},
		Prefetch: &Prefetch{Scope: "none"},
	}
}

// Write stores c under dir as name and returns its path.
func (c Config) Write(t env.TB, dir, name string) string {
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
