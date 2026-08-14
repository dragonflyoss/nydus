/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"encoding/base64"
	"os"

	"github.com/distribution/reference"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

// registryBackendConfig is the `backend.config` section for the registry
// backend understood by `nydus fuse --config`.
type registryBackendConfig struct {
	// Addr is the registry address including the scheme; the scheme selects
	// between TLS (`https://`) and plain HTTP (`http://`).
	Addr       string      `yaml:"addr"`
	Repository string      `yaml:"repository"`
	Auth       string      `yaml:"auth,omitempty"`
	HTTP       httpSection `yaml:"http"`
}

type httpSection struct {
	TLS tlsSection `yaml:"tls"`
}

type tlsSection struct {
	SkipVerify bool `yaml:"skip_verify"`
}

type backendSection struct {
	Type   string                `yaml:"type"`
	Config registryBackendConfig `yaml:"config"`
}

type storageSection struct {
	Dir string `yaml:"dir"`
}

type prefetchSection struct {
	Scope string `yaml:"scope"`
}

type storageConfig struct {
	Backend  backendSection  `yaml:"backend"`
	Storage  storageSection  `yaml:"storage"`
	Prefetch prefetchSection `yaml:"prefetch"`
}

// prefetchScope maps the prefetch toggle to a `prefetch.scope` value:
// "ondemand" warms the recorded hot set when prefetch is enabled, "none"
// keeps every read fully on-demand otherwise.
func prefetchScope(enable bool) string {
	if enable {
		return "ondemand"
	}
	return "none"
}

// WriteRegistryConfig derives a registry-backed storage config for img, writes
// it to configPath, and returns the rendered YAML. The registry address and
// repository are parsed from the image reference; credentials, TLS and HTTP
// settings come from the provider's reg side (source or target) used to pull
// the image. Blob prefetch runs only when prefetchEnable is set (a live mount
// wants production-like warmup, while check and optimize want fully on-demand
// reads).
func WriteRegistryConfig(provider *remote.Provider, reg remote.Side, img *Image, cacheDir, configPath string, prefetchEnable bool) (string, error) {
	named, err := reference.ParseNormalizedNamed(img.Ref)
	if err != nil {
		return "", errors.Wrapf(err, "parse image reference %q", img.Ref)
	}
	host := reference.Domain(named)
	repo := reference.Path(named)
	// The normalized Docker Hub domain is not the actual registry endpoint.
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}

	scheme := "https"
	if provider.PlainHTTP(reg) {
		scheme = "http"
	}

	var auth string
	if username, password, err := provider.Credentials(host); err == nil && username != "" {
		auth = basicAuthConfig(username, password)
	}

	cfg := storageConfig{
		Backend: backendSection{
			Type: "registry",
			Config: registryBackendConfig{
				Addr:       scheme + "://" + host,
				Repository: repo,
				Auth:       auth,
				HTTP: httpSection{
					TLS: tlsSection{SkipVerify: provider.Insecure(reg)},
				},
			},
		},
		Storage:  storageSection{Dir: cacheDir},
		Prefetch: prefetchSection{Scope: prefetchScope(prefetchEnable)},
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", errors.Wrap(err, "marshal storage config")
	}
	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		return "", errors.Wrapf(err, "write storage config %q", configPath)
	}
	return string(out), nil
}

func basicAuthConfig(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}
