/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containerd/log"
)

// defaultDockerConfigPaths are kubelet's docker config.json search paths for
// a root process, its root directory, $HOME/.docker and /.docker, without
// the working directory kubelet also searches, which means nothing to a
// service, refer to
// https://github.com/kubernetes/kubernetes/blob/6575724b63e50cd5dd454e774bc293c6de1e4e12/pkg/credentialprovider/config.go.
var defaultDockerConfigPaths = []string{
	"/var/lib/kubelet/config.json",
	"/root/.docker/config.json",
	"/.docker/config.json",
}

// authConfig is an entry of a docker config's auths.
type authConfig struct {
	// Username is the registry user name.
	Username string `json:"username,omitempty"`

	// Password is the registry password.
	Password string `json:"password,omitempty"`

	// Auth is the base64 username:password, preferred over Username and
	// Password.
	Auth string `json:"auth,omitempty"`

	// IdentityToken is an OAuth refresh token, unsupported.
	IdentityToken string `json:"identitytoken,omitempty"`

	// RegistryToken is a bearer token, unsupported.
	RegistryToken string `json:"registrytoken,omitempty"`
}

// decodeAuth decodes the auth field, padded or not, into a username and a
// password, refer to
// https://github.com/kubernetes/kubernetes/blob/6575724b63e50cd5dd454e774bc293c6de1e4e12/pkg/credentialprovider/config.go.
func (a *authConfig) decodeAuth() (string, string, error) {
	encoding := base64.RawStdEncoding
	if strings.HasSuffix(strings.TrimSpace(a.Auth), "=") {
		encoding = base64.StdEncoding
	}

	decoded, err := encoding.DecodeString(a.Auth)
	if err != nil {
		return "", "", err
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", errors.New("auth is not base64 username:password")
	}

	return username, password, nil
}

// dockerConfigJSON is a docker config.json, also the .dockerconfigjson key of
// a kubernetes.io/dockerconfigjson secret.
type dockerConfigJSON struct {
	// Auths holds the credentials by registry.
	Auths map[string]authConfig `json:"auths"`

	// CredsStore names a credential helper for every registry, unsupported.
	CredsStore string `json:"credsStore,omitempty"`

	// CredHelpers names a credential helper per registry, unsupported.
	CredHelpers map[string]string `json:"credHelpers,omitempty"`
}

// dockerConfigFile is a docker config.json as it was read.
type dockerConfigFile struct {
	// path is the file.
	path string

	// modTime is the modification time of the file when it was read.
	modTime time.Time

	// size is the size of the file when it was read.
	size int64

	// keyring indexes the auths of the file.
	keyring *keyring
}

// dockerConfigProvider provides the credentials of a docker config.json.
type dockerConfigProvider struct {
	// paths are the files searched, the first one that reads is used.
	paths []string

	// last is the file read last.
	last atomic.Pointer[dockerConfigFile]
}

// newDockerConfigProvider returns a provider reading the docker config at
// path or, when empty, the first one found in kubelet's search paths.
func newDockerConfigProvider(path string) *dockerConfigProvider {
	paths := defaultDockerConfigPaths
	if path != "" {
		paths = []string{path}
	}

	return &dockerConfigProvider{paths: paths}
}

// lookup returns the credentials matching target.
func (d *dockerConfigProvider) lookup(ctx context.Context, target registryKey) []credential {
	return d.load(ctx).lookup(target)
}

// load returns the keyring of the first file that reads, read again only
// when its modification time or size changed. A file that fails to read is
// skipped for the next one, as kubelet does. The file read last is the
// exception: its keyring is kept, as it was most likely caught half written.
func (d *dockerConfigProvider) load(ctx context.Context) *keyring {
	for _, path := range d.paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		last := d.last.Load()
		if last != nil && last.path != path {
			last = nil
		}

		if last != nil && last.modTime.Equal(info.ModTime()) && last.size == info.Size() {
			return last.keyring
		}

		k, err := d.read(ctx, path)
		if err != nil {
			if last != nil {
				log.G(ctx).WithError(err).WithField("path", path).Warn("keep the docker config read last")
				return last.keyring
			}

			log.G(ctx).WithError(err).WithField("path", path).Warn("skip docker config")
			continue
		}

		d.last.Store(&dockerConfigFile{path: path, modTime: info.ModTime(), size: info.Size(), keyring: k})
		return k
	}

	return &keyring{}
}

// read indexes the auths of a docker config.json.
func (d *dockerConfigProvider) read(ctx context.Context, path string) (*keyring, error) {
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
