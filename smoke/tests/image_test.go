// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/image-service/smoke/tests/tool"
)

func makeImageTest(t *testing.T, ctx tool.Context, source string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		// Prepare work directory
		ctx.PrepareWorkDir(t)
		defer ctx.Destroy(t)

		// Prepare options
		ociRefSuffix := ""
		enableOCIRef := ""
		if ctx.Build.OCIRef {
			ociRefSuffix = "-oci-ref"
			enableOCIRef = "--oci-ref"
		}
		target := fmt.Sprintf("%s-nydus-v%s%s", source, ctx.Build.FSVersion, ociRefSuffix)
		fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
		if ctx.Binary.NydusifyOnlySupportV5 {
			fsVersion = ""
		}
		compressor := "--compressor lz4_block"
		if ctx.Binary.NydusifyNotSupportCompressor {
			compressor = ""
		}

		// Convert image
		convertCmd := fmt.Sprintf(
			"%s convert --source %s --target %s %s %s --nydus-image %s --work-dir %s %s",
			ctx.Binary.Nydusify, source, target, fsVersion, enableOCIRef, ctx.Binary.Builder, ctx.Env.WorkDir, compressor,
		)
		tool.Run(t, convertCmd)

		// Check image
		nydusifyPath := ctx.Binary.Nydusify
		if ctx.Binary.NydusifyChecker != "" {
			nydusifyPath = ctx.Binary.NydusifyChecker
		}
		checkCmd := fmt.Sprintf(
			"%s check --source %s --target %s --nydus-image %s --nydusd %s --work-dir %s",
			nydusifyPath, source, target, ctx.Binary.Builder, ctx.Binary.Nydusd, filepath.Join(ctx.Env.WorkDir, "check"),
		)
		tool.Run(t, checkCmd)
	}
}

func TestImage(t *testing.T) {
	images := []string{"nginx:latest"}
	fsVersions := []string{"5", "6"}
	// True is for zran images
	ociRefs := []bool{false, true}

	for _, image := range images {
		sourceImage := tool.PrepareImage(t, image)
		for _, fsVersion := range fsVersions {
			for _, ociRef := range ociRefs {
				if fsVersion == "5" && ociRef {
					continue
				}

				ctx := tool.DefaultContext()
				ctx.Build.FSVersion = fsVersion
				ctx.Build.OCIRef = ociRef

				name := fmt.Sprintf("image=%s,fs_version=%s,zran=%v", image, fsVersion, ociRef)
				t.Run(name, makeImageTest(t, *ctx, sourceImage))
			}
		}
	}
}
