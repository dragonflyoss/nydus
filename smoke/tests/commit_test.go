// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type CommitTestSuite struct {
	t *testing.T
}

func (c *CommitTestSuite) TestCommitContainer() test.Generator {
	scenarios := tool.DescartesIterator{}
	scenarios.
		Dimension(paramImage, []interface{}{"ubuntu:latest"}).
		Dimension(paramFSVersion, []interface{}{"5", "6"})

	return func() (name string, testCase test.Case) {
		if !scenarios.HasNext() {
			return
		}
		scenario := scenarios.Next()
		ctx := tool.DefaultContext(c.t)
		ctx.Build.FSVersion = scenario.GetString(paramFSVersion)

		image, committedImage := c.prepareImage(c.t, ctx, scenario.GetString(paramImage))
		return scenario.Str(), func(_ *testing.T) {
			c.TestCommitAndCheck(*ctx, image, committedImage)
		}
	}
}

func (c *CommitTestSuite) TestCommitAndCheck(ctx tool.Context, image, commmitedImage string) {
	// run nydus contaienr
	containerName := uuid.NewString()
	runContainerCmd := fmt.Sprintf("sudo nerdctl --snapshotter nydus run -d -t --insecure-registry --name=%s %s sh", containerName, image)
	containerID := strings.Trim(tool.RunWithOutput(runContainerCmd), "\n")
	defer tool.ClearContainer(c.t, image, "nydus", containerName)

	// make some modifications in the read-write layer for commit action
	filePath := path.Join(ctx.Env.WorkDir, "commit")
	_, err := os.Create(filePath)
	require.NoError(c.t, err)
	defer ctx.Destroy(c.t)

	modifyCmd := fmt.Sprintf("echo \"This is Nydus commit\" > %s && sudo nerdctl cp %s %s:/root/", filePath, filePath, containerID)
	tool.RunWithoutOutput(c.t, modifyCmd)

	// commit container
	committedContainerName := fmt.Sprintf("%s-committed", containerName)
	commitCmd := fmt.Sprintf("sudo %s commit --container %s --target %s", ctx.Binary.Nydusify, containerID, commmitedImage)
	tool.RunWithoutOutput(c.t, commitCmd)

	// run committed container
	runCommittedContainerCmd := fmt.Sprintf("sudo nerdctl --snapshotter nydus run  -d -t --insecure-registry --name=%s %s sh", committedContainerName, commmitedImage)
	tool.RunWithOutput(runCommittedContainerCmd)
	defer tool.ClearContainer(c.t, commmitedImage, "nydus", committedContainerName)

	// check committed file content
	checkFileContent(c.t, committedContainerName, "/root/commit", "This is Nydus commit")
}

func (c *CommitTestSuite) prepareImage(t *testing.T, ctx *tool.Context, image string) (string, string) {
	ctx.PrepareWorkDir(t)
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

	// convert image
	convertCmd := fmt.Sprintf("%s %s convert --source %s --target %s --nydus-image %s --work-dir %s %s %s",
		ctx.Binary.Nydusify, logLevel, source, target, ctx.Binary.Builder, ctx.Env.WorkDir, fsVersion, enableOCIRef)
	tool.RunWithoutOutput(t, convertCmd)

	return target, fmt.Sprintf("%s-committed", target)
}

func checkFileContent(t *testing.T, containerName, path, content string) {
	nerdctlExec(t, containerName, fmt.Sprintf("stat %s && grep -Fxq '%s' %s", path, content, path))
}

func nerdctlExec(t *testing.T, containerName, cmd string) {
	tool.Run(t, fmt.Sprintf("nerdctl exec %s sh -c \"%s\"", containerName, cmd))
}

func TestCommit(t *testing.T) {
	test.Run(t, &CommitTestSuite{t: t})
}
