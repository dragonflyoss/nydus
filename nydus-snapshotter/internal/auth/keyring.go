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
	"errors"
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

// credential is an auths entry found by a keyring lookup.
type credential struct {
	// authConfig is the auths entry.
	authConfig

	// key is the keyring key the entry is indexed under.
	key string

	// source names where the entry comes from, a secret or a file.
	source string
}

// basic returns the base64 username:password of the credential, "" when it
// holds a token or no username, as kubelet only reads username and password.
func (c *credential) basic() string {
	if c.IdentityToken != "" || c.RegistryToken != "" {
		return ""
	}

	username, password := c.Username, c.Password
	if c.Auth != "" {
		var err error
		if username, password, err = decodeAuth(c.Auth); err != nil {
			return ""
		}
	}

	if username == "" {
		return ""
	}

	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// decodeAuth decodes an auth field, padded or not, into a username and a
// password, refer to
// https://github.com/kubernetes/kubernetes/blob/6575724b63e50cd5dd454e774bc293c6de1e4e12/pkg/credentialprovider/config.go.
func decodeAuth(field string) (string, string, error) {
	encoding := base64.RawStdEncoding
	if strings.HasSuffix(strings.TrimSpace(field), "=") {
		encoding = base64.StdEncoding
	}

	decoded, err := encoding.DecodeString(field)
	if err != nil {
		return "", "", err
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", errors.New("auth is not base64 username:password")
	}

	return username, password, nil
}

// keyring indexes credentials by registry key: a host, which may hold
// wildcards, and an optional path.
type keyring struct {
	// index holds the keys in insertion order.
	index []string

	// creds holds the credentials of each key in insertion order.
	creds map[string][]credential
}

// add indexes the auths of a source after the credentials already added.
func (k *keyring) add(source string, auths map[string]authConfig) {
	if k.creds == nil {
		k.creds = make(map[string][]credential)
	}

	// Sort the registries, so aliases of one key keep a stable order.
	for _, addr := range slices.Sorted(maps.Keys(auths)) {
		// An empty entry, as docker login with a credsStore writes, means
		// anonymous access, as containerd's ParseAuth and
		// go-containerregistry's keychain read it.
		if auths[addr] == (authConfig{}) {
			continue
		}

		key, err := registryKey(addr)
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

// lookup returns the credentials whose key matches target, a schemeless
// host/repository, the most specific key first.
func (k *keyring) lookup(target string) []credential {
	var keys []string
	for _, key := range k.index {
		// Both key and target are schemeless, the scheme is removed in add.
		if matched, _ := urlsMatchStr(key, target); matched {
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

// registryKey returns the keyring key of a docker config registry: its host
// and path without scheme, with /v1/ and /v2/ meaning the host only.
func registryKey(addr string) (string, error) {
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
	effectivePath := parsed.Path
	if strings.HasPrefix(effectivePath, "/v2/") || strings.HasPrefix(effectivePath, "/v1/") {
		effectivePath = effectivePath[3:]
	}

	host := canonicalHost(parsed.Host)
	if len(effectivePath) > 0 && effectivePath != "/" {
		return host + effectivePath, nil
	}

	return host, nil
}

// canonicalHost maps Docker Hub's hosts to docker.io, so a docker.io image
// matches the https://index.docker.io/v1/ key as kubelet's default registry
// fallback does.
func canonicalHost(host string) string {
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return registry.DockerHubHost
	default:
		return host
	}
}

// urlsMatchStr is urlsMatch on schemeless strings.
func urlsMatchStr(glob string, target string) (bool, error) {
	globURL, err := parseSchemelessURL(glob)
	if err != nil {
		return false, err
	}

	targetURL, err := parseSchemelessURL(target)
	if err != nil {
		return false, err
	}

	return urlsMatch(globURL, targetURL)
}

// parseSchemelessURL parses a schemeless url: url.Parse requires a scheme, so
// add one and clear it from the result.
func parseSchemelessURL(schemelessURL string) (*url.URL, error) {
	parsed, err := url.Parse("https://" + schemelessURL)
	if err != nil {
		return nil, err
	}

	parsed.Scheme = ""
	return parsed, nil
}

// splitURL splits the host name into parts, and returns the port.
func splitURL(url *url.URL) ([]string, string) {
	host, port, err := net.SplitHostPort(url.Host)
	if err != nil {
		// The host has no port.
		host, port = url.Host, ""
	}

	return strings.Split(host, "."), port
}

// urlsMatch reports whether the target url matches the glob url, which may
// have wildcards in host name parts: *.docker.io matches blah.docker.io but
// not not.right.io. Ports must be equal and the glob's path a prefix of the
// target's.
func urlsMatch(globURL *url.URL, targetURL *url.URL) (bool, error) {
	globURLParts, globPort := splitURL(globURL)
	targetURLParts, targetPort := splitURL(targetURL)
	if globPort != targetPort {
		return false, nil
	}

	if len(globURLParts) != len(targetURLParts) {
		return false, nil
	}

	if !strings.HasPrefix(targetURL.Path, globURL.Path) {
		return false, nil
	}

	for i, globURLPart := range globURLParts {
		matched, err := filepath.Match(globURLPart, targetURLParts[i])
		if err != nil {
			return false, err
		}

		if !matched {
			return false, nil
		}
	}

	return true, nil
}
