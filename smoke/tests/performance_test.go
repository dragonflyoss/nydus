// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/google/uuid"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshoooter, nydusd, nydus-image and nydusify.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.

type PerformanceTestSuite struct {
	t                 *testing.T
	testImage         string
	testContainerName string
}

func (p *PerformanceTestSuite) TestPerformance(t *testing.T) {
	ctx := tool.DefaultContext(p.t)
	// choose test mode
	mode := os.Getenv("PERFORMANCE_TEST_MODE")
	if mode == "" {
		mode = "fs-version-6"
	}
	switch mode {
	case "fs-version-5":
		ctx.Build.FSVersion = "5"
	case "fs-version-6":
		ctx.Build.FSVersion = "6"
	case "zran":
		ctx.Build.OCIRef = true
	default:
		p.t.Fatalf("PerformanceTest don't support %s mode", mode)
	}
	// choose test image
	image := os.Getenv("PERFORMANCE_TEST_IMAGE")

	if image == "" {
		image = "wordpress:6.1.1"
	} else {
		if !tool.SupportContainerImage(tool.ImageRepo(p.t, image)) {
			p.t.Fatalf("Unsupport image " + image)
		}
	}
	// prepare test image
	p.prepareTestImage(p.t, ctx, mode, image)

	// run Contaienr
	p.testContainerName = uuid.NewString()
	tool.RunContainer(p.t, p.testImage, p.testContainerName, mode)
	clearContainer(p.t, p.testImage, p.testContainerName)
}

func (p *PerformanceTestSuite) prepareTestImage(t *testing.T, ctx *tool.Context, mode string, image string) {
	if p.testImage != "" {
		return
	}

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)
	source := tool.PrepareImage(t, image)

	// Prepare options
	target := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())
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
	tool.RunWithoutOutput(t, convertCmd)
	p.testImage = target
}

func clearContainer(t *testing.T, image string, containerName string) {
	tool.RunWithoutOutput(t, fmt.Sprintf("sudo nerdctl --snapshotter nydus rm -f %s", containerName))
	tool.RunWithoutOutput(t, fmt.Sprintf("sudo nerdctl --snapshotter nydus image rm %s", image))
}

func TestPerformance(t *testing.T) {
	if os.Getenv("PERFORMANCE_TEST") == "" {
		t.Skip("skipping performance test")
	}
	test.Run(t, &PerformanceTestSuite{t: t})
}
