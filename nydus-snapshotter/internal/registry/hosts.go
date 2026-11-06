/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package registry

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
	"github.com/containerd/errdefs"
	"github.com/pelletier/go-toml/v2"
)

const (
	// DockerHubHost is the host image references name Docker Hub by.
	DockerHubHost = "docker.io"

	// dockerHubAddr is the registry address serving Docker Hub.
	dockerHubAddr = "https://registry-1.docker.io"

	// defaultHostDir is the host directory applying to every host.
	defaultHostDir = "_default"

	// hostsFile is the host config file in a host directory.
	hostsFile = "hosts.toml"
)

// Endpoint is the registry endpoint config a nydus daemon can express.
type Endpoint struct {
	// Addr is the registry origin with an optional path prefix, e.g.
	// https://registry-1.docker.io.
	Addr string

	// SkipVerify skips TLS certificate verification.
	SkipVerify bool

	// CACerts are CA certificate files trusted besides the system roots.
	CACerts []string
}

// hostFile is the subset of a hosts.toml a nydus daemon can express, refer to
// https://github.com/containerd/containerd/blob/main/docs/hosts.md. [host]
// mirror tables are ignored: a daemon reads from one registry.
type hostFile struct {
	// Server is the upstream registry address.
	Server string `toml:"server"`

	// CACert is one CA file path or a list of them.
	CACert any `toml:"ca"`

	// Client is a client certificate, which nydus cannot present.
	Client any `toml:"client"`

	// SkipVerify skips TLS certificate verification.
	SkipVerify *bool `toml:"skip_verify"`

	// OverridePath uses the server path as the API root, which nydus cannot
	// express.
	OverridePath bool `toml:"override_path"`
}

// Hosts resolves registry endpoints from a certs.d directory, as containerd's
// ConfigureHosts does, refer to
// https://github.com/containerd/containerd/blob/main/core/remotes/docker/config/hosts.go.
type Hosts struct {
	// configPath is the certs.d directory, empty for the defaults only.
	configPath string
}

// NewHosts returns the resolver of the certs.d directory at configPath.
func NewHosts(configPath string) *Hosts {
	return &Hosts{configPath: configPath}
}

// Resolve returns the registry endpoint of host, applying
// <configPath>/<host>/hosts.toml with containerd's directory lookup and
// defaults.
func (h *Hosts) Resolve(host string) (*Endpoint, error) {
	endpoint := h.defaultEndpoint(host)
	if h.configPath == "" {
		return endpoint, nil
	}

	dir, err := config.HostDirFromRoot(h.configPath)(host)
	if errors.Is(err, errdefs.ErrNotFound) {
		return endpoint, nil
	}

	if err != nil {
		return nil, fmt.Errorf("find host dir of %s: %w", host, err)
	}

	hostsPath := filepath.Join(dir, hostsFile)
	data, err := os.ReadFile(hostsPath)
	if errors.Is(err, os.ErrNotExist) {
		if err := endpoint.loadCertFiles(dir); err != nil {
			return nil, err
		}

		return endpoint, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read %s: %w", hostsPath, err)
	}

	var file hostFile
	if err := toml.NewDecoder(bytes.NewReader(data)).Decode(&file); err != nil {
		return nil, fmt.Errorf("decode %s: %w", hostsPath, err)
	}

	if err := endpoint.apply(&file, dir); err != nil {
		return nil, fmt.Errorf("apply %s: %w", hostsPath, err)
	}

	return endpoint, nil
}

// defaultEndpoint returns containerd's default endpoint of host.
func (h *Hosts) defaultEndpoint(host string) *Endpoint {
	if host == DockerHubHost {
		return &Endpoint{Addr: dockerHubAddr}
	}

	if !docker.IsLocalhost(host) {
		return &Endpoint{Addr: "https://" + host}
	}

	// Localhost speaks plain HTTP on a non-TLS port and skips verification
	// otherwise, as containerd's ConfigureHosts does.
	_, port, _ := net.SplitHostPort(host)
	if port == "" || port == "443" {
		return &Endpoint{Addr: "https://" + host, SkipVerify: true}
	}

	return &Endpoint{Addr: "http://" + host, SkipVerify: port != "80"}
}

// apply applies a hosts.toml of the host directory dir.
func (e *Endpoint) apply(file *hostFile, dir string) error {
	if file.Client != nil {
		return fmt.Errorf("client certificates are not supported by nydus: %w", errdefs.ErrNotImplemented)
	}

	// A _default server would need containerd's ?ns= query to reach the
	// right upstream, which nydus cannot send, so only its TLS settings apply.
	if file.Server != "" && filepath.Base(dir) != defaultHostDir {
		addr, err := file.addr()
		if err != nil {
			return err
		}

		e.Addr = addr
	}

	if file.SkipVerify != nil {
		e.SkipVerify = *file.SkipVerify
	}

	cas, err := file.caCerts()
	if err != nil {
		return err
	}

	for _, ca := range cas {
		if !filepath.IsAbs(ca) {
			ca = filepath.Join(dir, ca)
		}

		e.CACerts = append(e.CACerts, ca)
	}

	return nil
}

// loadCertFiles applies docker-style *.crt files of a host directory without
// hosts.toml, as containerd's loadCertFiles does.
func (e *Endpoint) loadCertFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read host dir %s: %w", dir, err)
	}

	for _, entry := range entries {
		switch filepath.Ext(entry.Name()) {
		case ".crt":
			e.CACerts = append(e.CACerts, filepath.Join(dir, entry.Name()))
		case ".cert", ".key":
			return fmt.Errorf("%s: client certificates are not supported by nydus: %w", filepath.Join(dir, entry.Name()), errdefs.ErrNotImplemented)
		}
	}

	return nil
}

// addr returns the server as the origin and path prefix a daemon takes,
// parsed as containerd's parseHostConfig does: a server without a scheme is
// https, and the /v2 API root, which the daemon appends itself, is stripped,
// refer to https://github.com/containerd/containerd/blob/main/core/remotes/docker/config/hosts.go.
func (f *hostFile) addr() (string, error) {
	if f.OverridePath {
		return "", fmt.Errorf("server %q: override_path is not supported by nydus: %w", f.Server, errdefs.ErrNotImplemented)
	}

	server := f.Server
	if !strings.HasPrefix(server, "http") {
		server = "https://" + server
	}

	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("parse server %q: %w", f.Server, err)
	}

	if u.Path != "" {
		u.Path = strings.TrimSuffix(strings.TrimSuffix(path.Clean(u.Path), "/v2"), "/")
	}

	return u.String(), nil
}

// caCerts returns the ca key, a string or a string array, as a slice.
func (f *hostFile) caCerts() ([]string, error) {
	switch ca := f.CACert.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{ca}, nil
	case []any:
		cas := make([]string, 0, len(ca))
		for _, item := range ca {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("decode ca: unexpected %T in list", item)
			}

			cas = append(cas, s)
		}

		return cas, nil
	default:
		return nil, fmt.Errorf("decode ca: unexpected type %T", ca)
	}
}
