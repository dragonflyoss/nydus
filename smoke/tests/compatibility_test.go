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
	images := []string{"nginx:latest"}
	fsVersions := []string{"5", "6"}

	builderVersions := []string{"v0.1.0", "v2.1.2", "latest"}
	nydusifyVersions := []string{"v0.1.0", "v2.1.2", "latest"}
	nydusdVersions := []string{"v0.1.0", "v2.1.2", "latest"}

	for _, image := range images {
		sourceImage := tool.PrepareImage(t, image)
		for _, fsVersion := range fsVersions {
			for _, builderVersion := range builderVersions {
				for _, nydusdVersion := range nydusdVersions {
					for _, nydusifyVersion := range nydusifyVersions {
						if builderVersion == "v0.1.0" && (nydusifyVersion != "v0.1.0" || fsVersion != "5") {
							continue
						}
						if nydusifyVersion == "v0.1.0" && (builderVersion != "v0.1.0" || fsVersion != "5") {
							continue
						}
						if nydusdVersion == "v0.1.0" && fsVersion != "5" {
							continue
						}

						nydusifyNotSupportCompressor := nydusifyVersion == "v0.1.0"
						nydusifyOnlySupportV5 := nydusifyVersion == "v0.1.0"

						builderPath := getFromEnv(t, "NYDUS_BUILDER", builderVersion)
						nydusdPath := getFromEnv(t, "NYDUS_NYDUSD", nydusdVersion)
						nydusifyPath := getFromEnv(t, "NYDUS_NYDUSIFY", nydusifyVersion)
						nydusifyCheckerPath := getFromEnv(t, "NYDUS_NYDUSIFY", "latest")

						name := fmt.Sprintf(
							"image=%s, fs_version=%s, nydus-image=%s, nydusd=%s, nydusify=%s",
							image, fsVersion, builderVersion, nydusdVersion, nydusifyVersion,
						)
						ctx := tool.DefaultContext()
						ctx.Binary = tool.BinaryContext{
							Builder:                      builderPath,
							Nydusd:                       nydusdPath,
							Nydusify:                     nydusifyPath,
							NydusifyChecker:              nydusifyCheckerPath,
							NydusifyOnlySupportV5:        nydusifyOnlySupportV5,
							NydusifyNotSupportCompressor: nydusifyNotSupportCompressor,
						}
						ctx.Build.FSVersion = fsVersion
						ctx.Build.Compressor = "lz4_block"
						ctx.Build.ChunkSize = "0x100000"
						ctx.Build.OCIRef = false

						t.Run(name, makeImageTest(t, *ctx, sourceImage))
					}
				}
			}
		}
	}
}
