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
	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(
			docker.NewDockerAuthorizer(
				docker.WithAuthClient(newHTTPClient(insecure)),
				docker.WithAuthCreds(credFunc),
			),
		),
		docker.WithClient(newHTTPClient(insecure)),
		docker.WithPlainHTTP(func(_ string) (bool, error) {
			return plainHTTP, nil
		}),
	)
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: registryHosts,
	})
}
