/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/pkg/errors"
)

// CredentialFunc accepts a registry host and returns the username and password
// to authenticate with it.
type CredentialFunc = func(host string) (string, string, error)

func newHTTPClient(skipTLSVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLSVerify,
			},
		},
	}
}

// transientStatusTransport returns a GET or HEAD the registry answers with a
// transient status as the typed error of that status. Containerd's fetcher
// reports such an answer as an untyped error, which the pull retries could not
// tell from a definitive one.
type transientStatusTransport struct{ http.RoundTripper }

func (t transientStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) ||
		!isTransientPushError(remoteserrors.ErrUnexpectedStatus{StatusCode: resp.StatusCode}) {
		return resp, err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil, remoteserrors.NewUnexpectedStatusErr(resp)
}

// newRegistryClient builds the client of registry requests, routing manifest
// and blob GETs through Dragonfly when it is enabled.
func newRegistryClient(skipTLSVerify bool) *http.Client {
	client := newHTTPClient(skipTLSVerify)
	client.Transport = transientStatusTransport{client.Transport}
	if dragonflyProxy != nil {
		client.Transport = &dragonflyTransport{base: client.Transport, getter: dragonflyProxy}
	}
	return client
}

// NewDockerConfigCredFunc reads the docker auth config file
// (`$DOCKER_CONFIG/config.json`, defaulting to `~/.docker`) to resolve
// credentials for a registry host.
func NewDockerConfigCredFunc() CredentialFunc {
	return func(host string) (string, string, error) {
		// Docker Hub auth is stored under the legacy v1 key.
		if host == "registry-1.docker.io" {
			host = "https://index.docker.io/v1/"
		}
		config := dockerconfig.LoadDefaultConfigFile(os.Stderr)
		authConfig, err := config.GetAuthConfig(host)
		if err != nil {
			return "", "", errors.Wrapf(err, "get auth config for %q", host)
		}
		return authConfig.Username, authConfig.Password, nil
	}
}

// NewResolver builds a docker registry resolver that handles authentication,
// optional TLS verification skipping, and optional plain HTTP.
func NewResolver(insecure, plainHTTP bool, credFunc CredentialFunc) remotes.Resolver {
	return newResolver(insecure, plainHTTP, credFunc, newRegistryClient(insecure))
}

func newResolver(insecure, plainHTTP bool, credFunc CredentialFunc, client *http.Client) remotes.Resolver {
	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(
			docker.NewDockerAuthorizer(
				docker.WithAuthClient(newHTTPClient(insecure)),
				docker.WithAuthCreds(credFunc),
			),
		),
		docker.WithClient(client),
		docker.WithPlainHTTP(func(_ string) (bool, error) {
			return plainHTTP, nil
		}),
	)
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: registryHosts,
	})
}
