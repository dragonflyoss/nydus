/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// The keyring is adapted from go-containerregistry's pkg/authn/kubernetes,
// which copies kubelet's credentialprovider keyring:
//
//	Copyright 2022 Google LLC All Rights Reserved.
//	Copyright 2014 The Kubernetes Authors.
//	Licensed under the Apache License, Version 2.0.
//
// refer to https://github.com/google/go-containerregistry/blob/bc0638f2d1730249dfef1f0230f3143150dc433a/pkg/authn/kubernetes/keychain.go
// and https://github.com/kubernetes/kubernetes/blob/6575724b63e50cd5dd454e774bc293c6de1e4e12/pkg/credentialprovider/keyring.go.

package auth

import (
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
)

// credential is an auths entry found by a keyring lookup.
type credential struct {
	// authConfig is the auths entry.
	authConfig

	// key is the keyring key the entry is indexed under.
	key registryKey

	// source names where the entry comes from, a secret or a file.
	source string
}

// basic returns the base64 username:password of the credential, "" when it
// holds no username or a token: a daemon cannot present a token, and the
// username:password docker stores beside one is a placeholder.
func (c *credential) basic() string {
	if c.IdentityToken != "" || c.RegistryToken != "" {
		return ""
	}

	username, password := c.Username, c.Password
	if c.Auth != "" {
		var err error
		if username, password, err = c.decodeAuth(); err != nil {
			return ""
		}
	}

	if username == "" {
		return ""
	}

	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// keyring indexes credentials by registry key.
type keyring struct {
	// index holds the keys in insertion order.
	index []registryKey

	// creds holds the credentials of each key in insertion order.
	creds map[registryKey][]credential
}

// add indexes the auths of a source after the credentials already added.
func (k *keyring) add(source string, auths map[string]authConfig) {
	if k.creds == nil {
		k.creds = make(map[registryKey][]credential)
	}

	// Sort the registries, so aliases of one key keep a stable order.
	for _, addr := range slices.Sorted(maps.Keys(auths)) {
		// An empty entry, as docker login with a credsStore writes, means
		// anonymous access, as containerd's ParseAuth and
		// go-containerregistry's keychain read it.
		if auths[addr] == (authConfig{}) {
			continue
		}

		key, err := parseRegistryKey(addr)
		if err != nil {
			log.L.WithError(err).WithField("source", source).Warn("skip invalid registry")
			continue
		}

		if _, ok := k.creds[key]; !ok {
			k.index = append(k.index, key)
		}

		k.creds[key] = append(k.creds[key], credential{authConfig: auths[addr], key: key, source: source})
	}
}

// lookup returns the credentials whose key matches target, the key of an
// image's host and repository, the most specific key first.
func (k *keyring) lookup(target registryKey) []credential {
	var keys []registryKey
	for _, key := range k.index {
		if matched, _ := key.matches(target); matched {
			keys = append(keys, key)
		}
	}

	// Reverse sort the keys, so more specific keys match first: for
	// quay.io/coreos/etcd, quay.io/coreos comes before quay.io.
	slices.Sort(keys)
	slices.Reverse(keys)

	var creds []credential
	for _, key := range keys {
		creds = append(creds, k.creds[key]...)
	}

	return creds
}

// registryKey is a keyring key: a schemeless host, which may hold wildcards,
// and an optional path.
type registryKey string

// newRegistryKey returns the key of a host and a path. Docker Hub's hosts map
// to docker.io, so a docker.io image matches the https://index.docker.io/v1/
// key as kubelet's default registry fallback does.
func newRegistryKey(host, path string) registryKey {
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		host = registry.DockerHubHost
	}

	if path == "" || path == "/" {
		return registryKey(host)
	}

	return registryKey(host + path)
}

// parseRegistryKey returns the key of a docker config registry: its host and
// path without scheme, with /v1/ and /v2/ meaning the host only.
func parseRegistryKey(addr string) (registryKey, error) {
	value := addr
	if !strings.HasPrefix(value, "https://") && !strings.HasPrefix(value, "http://") {
		value = "https://" + value
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse registry %q: %w", addr, err)
	}

	// The docker client allows exact matches, foo.bar.com/namespace, and
	// hostname matches, foo.bar.com. It also considers /v2/ and /v1/
	// equivalent to the hostname, see ResolveAuthConfig in
	// docker/registry/auth.go.
	path := parsed.Path
	if strings.HasPrefix(path, "/v2/") || strings.HasPrefix(path, "/v1/") {
		path = path[3:]
	}

	return newRegistryKey(parsed.Host, path), nil
}

// matches reports whether target matches the key, which may have wildcards in
// host name parts: *.docker.io matches blah.docker.io but not not.right.io.
// Ports must be equal and the key's path a prefix of the target's.
func (k registryKey) matches(target registryKey) (bool, error) {
	parts, port, path, err := k.split()
	if err != nil {
		return false, err
	}

	targetParts, targetPort, targetPath, err := target.split()
	if err != nil {
		return false, err
	}

	if port != targetPort || len(parts) != len(targetParts) || !strings.HasPrefix(targetPath, path) {
		return false, nil
	}

	for i, part := range parts {
		matched, err := filepath.Match(part, targetParts[i])
		if err != nil {
			return false, err
		}

		if !matched {
			return false, nil
		}
	}

	return true, nil
}

// split returns the host name parts, the port and the path of the key.
func (k registryKey) split() ([]string, string, string, error) {
	// url.Parse requires a scheme.
	parsed, err := url.Parse("https://" + string(k))
	if err != nil {
		return nil, "", "", err
	}

	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		// The host has no port.
		host, port = parsed.Host, ""
	}

	return strings.Split(host, "."), port, parsed.Path, nil
}
