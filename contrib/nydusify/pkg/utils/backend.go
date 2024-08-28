package utils

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/distribution/reference"
	dockerconfig "github.com/docker/cli/cli/config"
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
	URL      string `json:"url"`
	Fallback bool   `json:"fallback"`
	PingURL  string `json:"ping_url"`
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
