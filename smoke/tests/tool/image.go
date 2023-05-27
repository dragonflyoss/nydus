// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"os"
	"testing"
)

type Registry struct {
	containerID string
}

func NewRegistry() *Registry {
	registryPort := os.Getenv("REGISTRY_PORT")
	containerID := RunWithOutput(fmt.Sprintf("docker run -d -it --rm -p %s:5000 registry:2", registryPort))
	return &Registry{
		containerID: containerID,
	}
}

func (reg *Registry) Destroy() {
	RunWithOutput(fmt.Sprintf("docker rm -f %s", reg.containerID))
}

func PrepareImage(t *testing.T, source string) string {
	registryPort := os.Getenv("REGISTRY_PORT")
	Run(t, fmt.Sprintf("docker pull %s", source))
	target := fmt.Sprintf("localhost:%s/%s", registryPort, source)
	Run(t, fmt.Sprintf("docker tag %s %s", source, target))
	Run(t, fmt.Sprintf("docker push %s", target))
	return target
}
