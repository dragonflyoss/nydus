// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshotter, nydusd, nydus-image and nydusify.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.

type PerformanceTestSuite struct {
	t                 *testing.T
	testImage         string
	testContainerName string
}

func (p *PerformanceTestSuite) TestPerformance(_ *testing.T) {
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
			p.t.Fatalf("Unsupport %s image ", image)
		}
	}
	// prepare test image
	p.prepareTestImage(p.t, ctx, image)

	// run Container
	p.testContainerName = uuid.NewString()
	tool.RunContainerWithBaseline(p.t, p.testImage, p.testContainerName, mode)
}

func (p *PerformanceTestSuite) prepareTestImage(t *testing.T, ctx *tool.Context, image string) {
	if p.testImage != "" {
		return
	}
	source := tool.PrepareImage(t, image)
	target := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())

	tool.ConvertImage(t, ctx, source, target)
	p.testImage = target
}

func TestPerformance(t *testing.T) {
	if os.Getenv("PERFORMANCE_TEST") == "" {
		t.Skip("skipping performance test")
	}
	test.Run(t, &PerformanceTestSuite{t: t})
}
