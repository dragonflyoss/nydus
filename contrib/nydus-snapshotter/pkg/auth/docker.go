/*
 * Copyright (c) 2021. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"os"

	dockerconfig "github.com/docker/cli/cli/config"
)

const (
	dockerHost          = "https://index.docker.io/v1/"
	convertedDockerHost = "registry-1.docker.io"
)

// FromDockerConfig finds auth for a given host in docker's config.json settings.
func FromDockerConfig(host string) *PassKeyChain {
	if len(host) == 0 {
		return nil
	}

	// The host of docker hub image will be converted to `registry-1.docker.io` in:
	// github.com/containerd/containerd/remotes/docker/registry.go
	// But we need use the key `https://index.docker.io/v1/` to find auth from docker config.
	if host == convertedDockerHost {
		host = dockerHost
	}

	// TODO: log to default logger
	config := dockerconfig.LoadDefaultConfigFile(os.Stderr)
	authConfig, err := config.GetAuthConfig(host)
	if err != nil {
		return nil
	}

	// Do not return empty auth. It makes caller life easier.
	if len(authConfig.Username) == 0 || len(authConfig.Password) == 0 {
		return nil
	}

	return &PassKeyChain{
		Username: authConfig.Username,
		Password: authConfig.Password,
	}
}
