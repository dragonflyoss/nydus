// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"os"
	"testing"

	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/stretchr/testify/require"
)

const (
	paramImage             = "image"
	paramNydusImageVersion = "nydus_image_version"
	paramNydusdVersion     = "nydusd_version"
	paramNydusifyVersion   = "nydusify_version"
)

type CompatibilityTestSuite struct {
	t              *testing.T
	preparedImages map[string]string
}

func (c *CompatibilityTestSuite) TestConvertImages() test.Generator {
	stableVersion := os.Getenv("NYDUS_STABLE_VERSION")
	require.NotEmpty(c.t, stableVersion, "please specify env `NYDUS_STABLE_VERSION` to run the compatibility test.")

	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramImage, []interface{}{"nginx:latest"}).
		Dimension(paramFSVersion, []interface{}{"5", "6"}).
		Dimension(paramNydusImageVersion, []interface{}{"v0.1.0", stableVersion, "latest"}).
		Dimension(paramNydusifyVersion, []interface{}{"v0.1.0", stableVersion, "latest"}).
		Dimension(paramNydusdVersion, []interface{}{"v0.1.0", stableVersion, "latest"}).
		Skip(func(param *tool.DescartesItem) bool {

			// Nydus-image 0.1.0 only works with nydus-nydusify 0.1.0, vice versa.
			// They both only work with rafs v5.
			if param.GetString(paramNydusImageVersion) == "v0.1.0" || param.GetString(paramNydusifyVersion) == "v0.1.0" {
				return param.GetString(paramNydusImageVersion) != "v0.1.0" ||
					param.GetString(paramNydusifyVersion) != "v0.1.0" ||
					param.GetString(paramFSVersion) != "5"
			}

			// Nydusd 0.1.0 only works with rafs v5.
			if param.GetString(paramNydusdVersion) == "v0.1.0" {
				return param.GetString(paramFSVersion) != "5"
			}

			return false
		})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()

		nydusifyNotSupportCompressor := scenario.GetString(paramNydusifyVersion) == "v0.1.0"
		nydusifyOnlySupportV5 := scenario.GetString(paramNydusifyVersion) == "v0.1.0"

		builderPath := tool.GetBinary(c.t, "NYDUS_BUILDER", scenario.GetString(paramNydusImageVersion))
		nydusdPath := tool.GetBinary(c.t, "NYDUS_NYDUSD", scenario.GetString(paramNydusdVersion))
		nydusifyPath := tool.GetBinary(c.t, "NYDUS_NYDUSIFY", scenario.GetString(paramNydusifyVersion))
		nydusifyCheckerPath := tool.GetBinary(c.t, "NYDUS_NYDUSIFY", "latest")

		ctx := tool.DefaultContext(c.t)
		ctx.Binary = tool.BinaryContext{
			Builder:                      builderPath,
			Nydusd:                       nydusdPath,
			Nydusify:                     nydusifyPath,
			NydusifyChecker:              nydusifyCheckerPath,
			NydusifyOnlySupportV5:        nydusifyOnlySupportV5,
			NydusifyNotSupportCompressor: nydusifyNotSupportCompressor,
		}
		ctx.Build.FSVersion = scenario.GetString(paramFSVersion)
		ctx.Build.Compressor = "lz4_block"
		ctx.Build.ChunkSize = "0x100000"
		ctx.Build.OCIRef = false
		ctx.Build.BatchSize = "0"

		image := c.prepareImage(c.t, scenario.GetString(paramImage))
		return scenario.Str(), func(t *testing.T) {
			imageTest := &ImageTestSuite{T: t}
			imageTest.TestConvertAndCopyImage(t, *ctx, image, false)
		}
	}
}

func (c *CompatibilityTestSuite) prepareImage(t *testing.T, image string) string {
	if c.preparedImages == nil {
		c.preparedImages = make(map[string]string)
	}
	loc, ok := c.preparedImages[image]
	if !ok {
		loc = tool.PrepareImage(t, image)
		c.preparedImages[image] = loc
	}
	return loc
}

func TestCompatibility(t *testing.T) {
	test.Run(t, &CompatibilityTestSuite{t: t})
}
