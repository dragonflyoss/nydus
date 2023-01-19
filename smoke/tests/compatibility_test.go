// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/dragonflyoss/image-service/smoke/tests/tool"
)

const (
	paramImage             = "image"
	paramNydusImageVersion = "nydus_image_version"
	paramNydusdVersion     = "nydusd_version"
	paramNydusifyVersion   = "nydusify_version"
)

func getFromEnv(t *testing.T, env, version string) string {
	version = strings.ReplaceAll(version, ".", "_")
	key := fmt.Sprintf("%s_%s", env, version)
	if version == "latest" {
		key = env
	}
	binary := os.Getenv(key)
	if binary == "" {
		t.Skipf("skip compatibility test because no env `%s` specified", key)
	}
	return binary
}

func TestCompatibility(t *testing.T) {

	params := tool.DescartesIterator{}
	params.
		Register(paramImage, []interface{}{"nginx:latest"}).
		Register(paramFSVersion, []interface{}{"5", "6"}).
		Register(paramNydusImageVersion, []interface{}{"v0.1.0", "v2.1.2", "latest"}).
		Register(paramNydusifyVersion, []interface{}{"v0.1.0", "v2.1.2", "latest"}).
		Register(paramNydusdVersion, []interface{}{"v0.1.0", "v2.1.2", "latest"}).
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

	preparedImages := make(map[string]string)
	for params.HasNext() {
		param := params.Next()

		image := param.GetString(paramImage)
		if _, ok := preparedImages[image]; !ok {
			preparedImages[image] = tool.PrepareImage(t, image)
		}

		nydusifyNotSupportCompressor := param.GetString(paramNydusifyVersion) == "v0.1.0"
		nydusifyOnlySupportV5 := param.GetString(paramNydusifyVersion) == "v0.1.0"

		builderPath := getFromEnv(t, "NYDUS_BUILDER", param.GetString(paramNydusImageVersion))
		nydusdPath := getFromEnv(t, "NYDUS_NYDUSD", param.GetString(paramNydusdVersion))
		nydusifyPath := getFromEnv(t, "NYDUS_NYDUSIFY", param.GetString(paramNydusifyVersion))
		nydusifyCheckerPath := getFromEnv(t, "NYDUS_NYDUSIFY", "latest")

		ctx := tool.DefaultContext()
		ctx.Binary = tool.BinaryContext{
			Builder:                      builderPath,
			Nydusd:                       nydusdPath,
			Nydusify:                     nydusifyPath,
			NydusifyChecker:              nydusifyCheckerPath,
			NydusifyOnlySupportV5:        nydusifyOnlySupportV5,
			NydusifyNotSupportCompressor: nydusifyNotSupportCompressor,
		}
		ctx.Build.FSVersion = param.GetString(paramFSVersion)
		ctx.Build.Compressor = "lz4_block"
		ctx.Build.ChunkSize = "0x100000"
		ctx.Build.OCIRef = false

		t.Run(param.Str(), makeImageTest(t, *ctx, preparedImages[image]))
	}
}
