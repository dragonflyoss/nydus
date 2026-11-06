/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/containerd/log"
)

// defaultDockerConfigPaths are kubelet's docker config.json search paths for
// a root process: its root directory, $HOME/.docker and /.docker, refer to
// https://github.com/kubernetes/kubernetes/blob/6575724b63e50cd5dd454e774bc293c6de1e4e12/pkg/credentialprovider/config.go.
var defaultDockerConfigPaths = []string{
	"/var/lib/kubelet/config.json",
	"/root/.docker/config.json",
	"/.docker/config.json",
}

// dockerConfig is the docker config.json credential source.
type dockerConfig struct {
	// paths are the files searched, the first one found is read.
	paths []string

	// mu guards path, modTime, size and keyring.
	mu sync.Mutex

	// path is the file keyring was read from.
	path string

	// modTime is the modification time of path when it was read.
	modTime time.Time

	// size is the size of path when it was read.
	size int64

	// keyring indexes the auths of path.
	keyring *keyring
}

// New docker config source, reading path or, when empty, the first file found
// in kubelet's search paths.
func newDockerConfig(path string) *dockerConfig {
	paths := defaultDockerConfigPaths
	if path != "" {
		paths = []string{path}
	}

	return &dockerConfig{paths: paths}
}

// lookup returns the credentials matching target.
func (d *dockerConfig) lookup(ctx context.Context, target string) []credential {
	return d.load(ctx).lookup(target)
}

// load returns the keyring of the first file read, read again only when its
// modification time or size changed. An unreadable file is skipped for the
// next one, as kubelet does.
func (d *dockerConfig) load(ctx context.Context) *keyring {
	for _, path := range d.paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		d.mu.Lock()
		k := d.keyring
		cached := k != nil && path == d.path && info.ModTime().Equal(d.modTime) && info.Size() == d.size
		d.mu.Unlock()
		if cached {
			return k
		}

		k, err = d.read(ctx, path)
		if err != nil {
			log.G(ctx).WithError(err).WithField("path", path).Warn("skip docker config")
			continue
		}

		d.mu.Lock()
		d.path, d.modTime, d.size, d.keyring = path, info.ModTime(), info.Size(), k
		d.mu.Unlock()
		return k
	}

	return &keyring{}
}

// read indexes the auths of a docker config.json.
func (d *dockerConfig) read(ctx context.Context, path string) (*keyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg dockerConfigJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.CredsStore != "" || len(cfg.CredHelpers) > 0 {
		log.G(ctx).WithField("path", path).Warn("docker config credsStore and credHelpers are unsupported, only auths is read")
	}

	k := &keyring{}
	k.add(path, cfg.Auths)
	return k, nil
}
