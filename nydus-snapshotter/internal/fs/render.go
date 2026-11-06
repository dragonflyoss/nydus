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

// renderOptions are the per-daemon values filled into the template.
type renderOptions struct {
	// cacheDir is the shared blob cache, storage.dir.
	cacheDir string

	// addr is the registry origin, backend.config.addr.
	addr string

	// repository is the image repository, backend.config.repository.
	repository string

	// auth is the base64 username:password, backend.config.auth.
	auth string

	// skipVerify skips TLS verification, backend.config.http.tls.skip_verify.
	skipVerify bool

	// caCert is the CA bundle, backend.config.http.tls.ca_cert.
	caCert string

	// dragonfly is backend.config.dragonfly, ignored without a scheduler.
	dragonfly config.DragonflyConfig

	// prefetchScope is prefetch.scope.
	prefetchScope string
}

// renderConfig writes the daemon's config to tmpfs; it holds the credential.
func (f *fileSystem) renderConfig(ctx context.Context, cfg *config.Config, d *Daemon, ref *registry.Reference, prefetchScope string) error {
	template, err := os.ReadFile(cfg.Nydusd.Template)
	if err != nil {
		return fmt.Errorf("read nydusd template: %w", err)
	}

	endpoint, err := f.hosts.Resolve(ref.Host)
	if err != nil {
		return err
	}

	credential, err := f.keychain.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("resolve credential of %s: %w", ref.Name, err)
	}

	opts := &renderOptions{
		cacheDir:      cfg.CacheDir(),
		addr:          endpoint.Addr,
		repository:    ref.Repository,
		auth:          credential,
		skipVerify:    endpoint.SkipVerify,
		dragonfly:     cfg.Nydusd.Dragonfly,
		prefetchScope: cmp.Or(prefetchScope, cfg.Nydusd.PrefetchScope),
	}

	// nydus trusts one CA file, so several are bundled.
	switch len(endpoint.CACerts) {
	case 0:
	case 1:
		opts.caCert = endpoint.CACerts[0]
	default:
		var bundle []byte
		for _, ca := range endpoint.CACerts {
			pem, err := os.ReadFile(ca)
			if err != nil {
				return fmt.Errorf("read ca %s: %w", ca, err)
			}

			bundle = append(append(bundle, pem...), '\n')
		}

		opts.caCert = filepath.Join(filepath.Dir(d.Config), "ca.pem")
		if err := continuity.AtomicWriteFile(opts.caCert, bundle, 0o644); err != nil {
			return err
		}
	}

	data, err := opts.render(template)
	if err != nil {
		return err
	}

	return continuity.AtomicWriteFile(d.Config, data, 0o600)
}

// document is a decoded YAML mapping.
type document map[string]any

// render fills the per-daemon values into a nydus-config template. The
// snapshotter owns these keys; every other key is passed through for nydus to
// validate, refer to the Storage config section of docs/nydus.md.
func (r *renderOptions) render(template []byte) ([]byte, error) {
	root := document{}
	if err := yaml.Unmarshal(template, &root); err != nil {
		return nil, fmt.Errorf("decode nydusd template: %w", err)
	}

	storage, err := root.child("storage")
	if err != nil {
		return nil, err
	}
	storage["dir"] = r.cacheDir

	prefetch, err := root.child("prefetch")
	if err != nil {
		return nil, err
	}
	prefetch["scope"] = r.prefetchScope

	backend, err := root.child("backend")
	if err != nil {
		return nil, err
	}
	backend["type"] = "registry"

	registryConfig, err := backend.child("config")
	if err != nil {
		return nil, err
	}
	registryConfig["addr"] = r.addr
	registryConfig["repository"] = r.repository
	delete(registryConfig, "auth")
	if r.auth != "" {
		registryConfig["auth"] = r.auth
	}

	if r.skipVerify || r.caCert != "" {
		httpConfig, err := registryConfig.child("http")
		if err != nil {
			return nil, err
		}

		tls, err := httpConfig.child("tls")
		if err != nil {
			return nil, err
		}
		tls["skip_verify"] = r.skipVerify
		if r.caCert != "" {
			tls["ca_cert"] = r.caCert
		}
	}

	if r.dragonfly.SchedulerEndpoint != "" {
		registryConfig["dragonfly"] = r.dragonfly
	}

	data, err := yaml.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("encode nydusd config: %w", err)
	}

	return data, nil
}

// child returns the mapping under key, creating it when absent.
func (d document) child(key string) (document, error) {
	v, ok := d[key]
	if !ok || v == nil {
		child := document{}
		d[key] = child
		return child, nil
	}

	switch child := v.(type) {
	case document:
		return child, nil
	case map[string]any:
		d[key] = document(child)
		return child, nil
	default:
		return nil, fmt.Errorf("nydusd template: %s is %T, want a mapping", key, v)
	}
}
