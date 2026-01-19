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
	target := fmt.Sprintf("localhost:%s/%s", registryPort, source)
	if _, err := RunWithCombinedOutput(fmt.Sprintf("docker pull %s", target)); err == nil {
		return target
	}
	if _, err := RunWithCombinedOutput(fmt.Sprintf("docker tag %s %s", source, target)); err != nil {
		Run(t, fmt.Sprintf("docker pull %s", source))
		Run(t, fmt.Sprintf("docker tag %s %s", source, target))
	}
	Run(t, fmt.Sprintf("docker push %s", target))
	return target
}

// ConvertImage converts source image to nydus image
func ConvertImage(t *testing.T, ctx *Context, source, target string) {
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	// Prepare options
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	if ctx.Binary.NydusifyOnlySupportV5 {
		fsVersion = ""
		logLevel = ""
	}
	enableOCIRef := ""
	if ctx.Build.OCIRef {
		enableOCIRef = "--oci-ref"
	}

	// Convert image
	convertCmd := fmt.Sprintf("%s %s convert --source %s --target %s --nydus-image %s --work-dir %s %s %s",
		ctx.Binary.Nydusify, logLevel, source, target, ctx.Binary.Builder, ctx.Env.WorkDir, fsVersion, enableOCIRef)
	Run(t, convertCmd)
}
