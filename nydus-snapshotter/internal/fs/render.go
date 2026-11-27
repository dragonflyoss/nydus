/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/continuity"
	"gopkg.in/yaml.v3"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
)

// renderOptions are the values of a nydus config, a daemon's or a preheat's.
type renderOptions struct {
	// nydusd holds what all daemons share: runtime_dir and the backend,
	// storage and prefetch sections.
	nydusd config.NydusdDaemonConfig

	// cacheDir is the shared blob cache, storage.dir.
	cacheDir string

	// addr is the registry origin, backend.config.addr.
	addr string

	// repository is the image repository, backend.config.repository.
	repository string

	// auth is the base64 username:password, backend.config.auth.
	auth string

	// registryToken is the bearer token, backend.config.registry_token.
	registryToken string

	// skipVerify skips TLS verification, backend.config.http.tls.skip_verify.
	skipVerify bool

	// caCert is the CA bundle, backend.config.http.tls.ca_cert.
	caCert string

	// prefetchScope is prefetch.scope.
	prefetchScope string
}

// render returns the nydus config, refer to the Storage config section of
// docs/nydus.md.
//
//	snapshotter config   nydusd.config, key for key
//	image reference      backend.config.{addr,repository}
//	keychain or preheat  backend.config.{auth,registry_token}
//	certs.d hosts.toml   backend.config.http.tls
//	nydus-prefetch label prefetch.scope
func (r *renderOptions) render() ([]byte, error) {
	registryConfig := r.nydusd.Backend.Config
	httpConfig := map[string]any{
		"request_timeout":      registryConfig.HTTP.RequestTimeout,
		"request_read_timeout": registryConfig.HTTP.RequestReadTimeout,
		"max_retries":          registryConfig.HTTP.MaxRetries,
	}
	if registryConfig.HTTP.Proxy.Addr != "" {
		httpConfig["proxy"] = registryConfig.HTTP.Proxy
	}

	if r.skipVerify || r.caCert != "" {
		tls := map[string]any{"skip_verify": r.skipVerify}
		if r.caCert != "" {
			tls["ca_cert"] = r.caCert
		}
		httpConfig["tls"] = tls
	}

	registry := map[string]any{
		"addr":       r.addr,
		"repository": r.repository,
		"http":       httpConfig,
		"fallback":   registryConfig.Fallback,
	}
	if r.auth != "" {
		registry["auth"] = r.auth
	}

	if r.registryToken != "" {
		registry["registry_token"] = r.registryToken
	}

	if registryConfig.Dragonfly.SchedulerEndpoint != "" {
		registry["dragonfly"] = registryConfig.Dragonfly
	}

	storage, prefetch := r.nydusd.Storage, r.nydusd.Prefetch
	storage.Dir, prefetch.Scope = r.cacheDir, r.prefetchScope

	data, err := yaml.Marshal(map[string]any{
		"runtime_dir": r.nydusd.RuntimeDir,
		"backend":     map[string]any{"type": "registry", "config": registry},
		"storage":     storage,
		"prefetch":    prefetch,
	})
	if err != nil {
		return nil, fmt.Errorf("encode nydusd config: %w", err)
	}

	return data, nil
}

// renderDaemonConfig renders the daemon's config, with the keychain's
// credential, and writes it into the daemon's runtime dir.
func (f *fileSystem) renderDaemonConfig(ctx context.Context, cfg *config.Config, d *Daemon, ref *registry.Reference, prefetchScope string) error {
	endpoint, err := f.hosts.Resolve(ref.Host)
	if err != nil {
		return err
	}

	credential, err := f.keychain.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("resolve credential of %s: %w", ref.Name, err)
	}

	return f.writeNydusConfig(cfg, ref, endpoint, d.RuntimeDir, d.ConfigPath, &renderOptions{
		auth:          credential,
		prefetchScope: cmp.Or(prefetchScope, cfg.Nydusd.Config.Prefetch.Scope),
	})
}

// writeNydusConfig fills in what every nydus process reading the image shares,
// renders the config and writes it to path in dir, on tmpfs because the
// config holds the credential.
func (f *fileSystem) writeNydusConfig(cfg *config.Config, ref *registry.Reference, endpoint *registry.Endpoint, dir, path string, opts *renderOptions) error {
	caCert, err := f.caBundle(endpoint.CACerts, dir)
	if err != nil {
		return err
	}

	opts.nydusd = cfg.Nydusd.Config
	opts.cacheDir = cfg.CacheDir()
	opts.addr = endpoint.Addr
	opts.repository = ref.Repository
	opts.skipVerify = endpoint.SkipVerify
	opts.caCert = caCert
	data, err := opts.render()
	if err != nil {
		return err
	}

	return continuity.AtomicWriteFile(path, data, 0o600)
}

// caBundle returns the one CA file nydus trusts: none, the only one, or a
// bundle of several written into dir.
func (f *fileSystem) caBundle(cas []string, dir string) (string, error) {
	switch len(cas) {
	case 0:
		return "", nil
	case 1:
		return cas[0], nil
	}

	var bundle []byte
	for _, ca := range cas {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return "", fmt.Errorf("read ca %s: %w", ca, err)
		}

		bundle = append(append(bundle, pem...), '\n')
	}

	path := filepath.Join(dir, "ca.pem")
	if err := continuity.AtomicWriteFile(path, bundle, 0o644); err != nil {
		return "", err
	}

	return path, nil
}
