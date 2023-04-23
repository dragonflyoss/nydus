// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"testing"
)

var list = []string{
	"alpine",
	"busybox",
	"ubuntu",
	"redis",
	"node",
	"python",
	"nginx",
	"golang",
	"wordpress",
	"mongo",
	"debian",
	// An alternative for open jdk image, see:
	// https://hub.docker.com/_/openjdk
	// https://github.com/docker-library/openjdk/issues/505
	"amazoncorretto",
	"ruby",
	"php",
	"tomcat",
}

func transfer(t *testing.T, ref string) {
	run(t, fmt.Sprintf("docker pull %s", ref), true)
	host := fmt.Sprintf("localhost:%d", registryPort)
	run(t, fmt.Sprintf("docker tag %s %s/%s", ref, host, ref), true)
	run(t, fmt.Sprintf("docker push %s/%s", host, ref), true)
}

func convert(t *testing.T, ref string, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)
	transfer(t, ref)
	nydusify := NewNydusify(registry, ref, fmt.Sprintf("%s-nydus", ref), "", "", fsVersion, "")
	nydusify.Convert(t)
	nydusify.Check(t)
}

func TestDockerHubImage(t *testing.T) {
	for _, ref := range list {
		convert(t, ref, "5")
		convert(t, ref, "6")
	}
}
