// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
)

func newDefaultClient(skipTLSVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
			TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLSVerify,
			},
		},
	}
}

// withCredentialFunc accepts host url parameter and returns with
// username, password and error.
type withCredentialFunc = func(string) (string, string, error)

// withRemote creates a remote instance, it uses the implementation of containerd
// docker remote to access image from remote registry.
func withRemote(ref string, insecure bool, credFunc withCredentialFunc) (*remote.Remote, error) {
	resolverFunc := func(retryWithHTTP bool) remotes.Resolver {
		registryHosts := docker.ConfigureDefaultRegistries(
			docker.WithAuthorizer(
				docker.NewDockerAuthorizer(
					docker.WithAuthClient(newDefaultClient(insecure)),
					docker.WithAuthCreds(credFunc),
				),
			),
			docker.WithClient(newDefaultClient(insecure)),
			docker.WithPlainHTTP(func(_ string) (bool, error) {
				return retryWithHTTP, nil
			}),
		)

		return docker.NewResolver(docker.ResolverOptions{
			Hosts: registryHosts,
		})
	}

	return remote.New(ref, resolverFunc)
}

// DefaultRemote creates a remote instance, it attempts to read docker auth config
// file `$DOCKER_CONFIG/config.json` to communicate with remote registry, `$DOCKER_CONFIG`
// defaults to `~/.docker`.
func DefaultRemote(ref string, insecure bool) (*remote.Remote, error) {
	return withRemote(ref, insecure, func(host string) (string, string, error) {
		// The host of docker hub image will be converted to `registry-1.docker.io` in:
		// github.com/containerd/containerd/remotes/docker/registry.go
		// But we need use the key `https://index.docker.io/v1/` to find auth from docker config.
		if host == "registry-1.docker.io" {
			host = "https://index.docker.io/v1/"
		}

		config := dockerconfig.LoadDefaultConfigFile(os.Stderr)
		authConfig, err := config.GetAuthConfig(host)
		if err != nil {
			return "", "", err
		}

		return authConfig.Username, authConfig.Password, nil
	})
}

// DefaultRemoteWithAuth creates a remote instance, it parses base64 encoded auth string
// to communicate with remote registry.
func DefaultRemoteWithAuth(ref string, insecure bool, auth string) (*remote.Remote, error) {
	return withRemote(ref, insecure, func(_ string) (string, string, error) {
		// Leave auth empty if no authorization be required
		if strings.TrimSpace(auth) == "" {
			return "", "", nil
		}
		decoded, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return "", "", errors.Wrap(err, "Decode base64 encoded auth string")
		}
		ary := strings.Split(string(decoded), ":")
		if len(ary) != 2 {
			return "", "", errors.New("Invalid base64 encoded auth string")
		}
		return ary[0], ary[1], nil
	})
}
