/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package registry

import (
	"fmt"
	"strings"

	"github.com/containerd/containerd/reference/docker"
)

type Image struct {
	Host string
	Repo string
}

func ConvertToVPCHost(registryHost string) string {
	parts := strings.Split(registryHost, ".")
	if strings.HasSuffix(parts[0], "-vpc") {
		return registryHost
	}
	parts[0] = fmt.Sprintf("%s-vpc", parts[0])
	return strings.Join(parts, ".")
}

func ParseImage(imageID string) (Image, error) {
	named, err := docker.ParseDockerRef(imageID)
	if err != nil {
		return Image{}, err
	}
	host := docker.Domain(named)
	repo := docker.Path(named)
	return Image{
		Host: host,
		Repo: repo,
	}, nil
}
