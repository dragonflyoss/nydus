package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/distribution/reference"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/pkg/errors"
)

type RegistryBackendConfig struct {
	Scheme     string             `json:"scheme"`
	Host       string             `json:"host"`
	Repo       string             `json:"repo"`
	Auth       string             `json:"auth,omitempty"`
	SkipVerify bool               `json:"skip_verify,omitempty"`
	Proxy      BackendProxyConfig `json:"proxy"`
}

type BackendProxyConfig struct {
	CacheDir       string `json:"cache_dir"`
	URL            string `json:"url"`
	Fallback       bool   `json:"fallback"`
	PingURL        string `json:"ping_url"`
	Timeout        int    `json:"timeout"`
	ConnectTimeout int    `json:"connect_timeout"`
}

func NewRegistryBackendConfig(parsed reference.Named, insecure bool) (RegistryBackendConfig, error) {
	proxyURL := os.Getenv("HTTP_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("HTTPS_PROXY")
	}

	backendConfig := RegistryBackendConfig{
		Scheme:     "https",
		Host:       reference.Domain(parsed),
		Repo:       reference.Path(parsed),
		SkipVerify: insecure,
		Proxy: BackendProxyConfig{
			URL:      proxyURL,
			Fallback: true,
		},
	}

	config := dockerconfig.LoadDefaultConfigFile(os.Stderr)
	authConfig, err := config.GetAuthConfig(backendConfig.Host)
	if err != nil {
		return backendConfig, errors.Wrap(err, "get docker registry auth config")
	}
	var auth string
	if authConfig.Username != "" && authConfig.Password != "" {
		auth = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", authConfig.Username, authConfig.Password)))
	}
	backendConfig.Auth = auth

	return backendConfig, nil
}

// The external backend configuration extracted from the manifest is missing the runtime configuration.
// Therefore, it is necessary to construct the runtime configuration using the available backend configuration.
func BuildRuntimeExternalBackendConfig(backendConfig, externalBackendConfigPath string) error {
	extBkdCfg := backend.Backend{}
	extBkdCfgBytes, err := os.ReadFile(externalBackendConfigPath)
	if err != nil {
		return errors.Wrap(err, "failed to read external backend config file")
	}

	if err := json.Unmarshal(extBkdCfgBytes, &extBkdCfg); err != nil {
		return errors.Wrap(err, "failed to unmarshal external backend config file")
	}

	bkdCfg := RegistryBackendConfig{}
	if err := json.Unmarshal([]byte(backendConfig), &bkdCfg); err != nil {
		return errors.Wrap(err, "failed to unmarshal registry backend config file")
	}

	proxyURL := os.Getenv("NYDUS_EXTERNAL_PROXY_URL")
	if proxyURL == "" {
		proxyURL = bkdCfg.Proxy.URL
	}
	cacheDir := os.Getenv("NYDUS_EXTERNAL_PROXY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = bkdCfg.Proxy.CacheDir
	}

	extBkdCfg.Backends[0].Config = map[string]interface{}{
		"scheme":          bkdCfg.Scheme,
		"host":            bkdCfg.Host,
		"repo":            bkdCfg.Repo,
		"auth":            bkdCfg.Auth,
		"timeout":         30,
		"connect_timeout": 5,
		"proxy": BackendProxyConfig{
			CacheDir: cacheDir,
			URL:      proxyURL,
			Fallback: true,
		},
	}

	extBkdCfgBytes, err = json.MarshalIndent(extBkdCfg, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal external backend config file")
	}
	if err = os.WriteFile(externalBackendConfigPath, extBkdCfgBytes, 0644); err != nil {
		return errors.Wrap(err, "failed to write external backend config file")
	}
	return nil
}
