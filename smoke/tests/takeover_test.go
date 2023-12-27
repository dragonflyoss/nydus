// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshotter, nydusd.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.

var (
	snapshotter           string
	takeoverTestImage     string
	snapshotterSystemSock string
)

type TakeoverTestSuit struct {
	t              *testing.T
	ctx            *tool.Context
	testImage      string
	snapshotterCli *tool.SnapshotterClient
}

func NewTakeoverTestSuit(t *testing.T) *TakeoverTestSuit {
	snapshotterCli := tool.NewSnapshotterClient(snapshotterSystemSock)
	ctx := tool.DefaultContext(t)

	// prepare and convert image
	sourceImage := tool.PrepareImage(t, takeoverTestImage)
	imageName := fmt.Sprintf("%s:nydus", sourceImage)
	tool.ConvertImage(t, ctx, sourceImage, imageName)

	return &TakeoverTestSuit{
		t:              t,
		ctx:            ctx,
		testImage:      imageName,
		snapshotterCli: snapshotterCli,
	}
}

func (f *TakeoverTestSuit) clear() {
	tool.RunWithoutOutput(f.t, fmt.Sprintf("sudo nerdctl --snapshotter %s image rm %s", snapshotter, f.testImage))
}

func (f *TakeoverTestSuit) rmContainer(conatinerName string) {
	tool.RunWithoutOutput(f.t, fmt.Sprintf("sudo nerdctl --snapshotter %s rm -f %s", snapshotter, conatinerName))
}

func (f *TakeoverTestSuit) TestFailover(t *testing.T) {
	imageName := f.testImage

	containerName := uuid.NewString()
	tool.RunContainerSimple(t, imageName, snapshotter, containerName, false)
	defer f.rmContainer(containerName)

	daemons, err := f.snapshotterCli.GetNydusDaemonInfos()
	require.NoError(t, err, "get nydus daemon infos")

	// kill the nydus daemons
	for _, daemon := range daemons {
		killCmd := fmt.Sprintf("kill -9 %d", daemon.Pid)
		tool.Run(t, killCmd)
	}

	// wait for the nydus daemons recover
	time.Sleep(5 * time.Second)

	// check the container by requesting its wait url
	runArgs := tool.GetRunArgs(t, imageName)
	resp, err := http.Get(runArgs.WaitURL)
	require.NoError(t, err, "access to the wait url of the recoverd container")
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("Failed to access the wait url of the recoverd container")
	}
}

func (f *TakeoverTestSuit) TestHotUpgrade(t *testing.T) {
	imageName := f.testImage

	containerName := uuid.NewString()
	tool.RunContainerSimple(t, imageName, snapshotter, containerName, false)
	defer f.rmContainer(containerName)

	// hot upgrade nydusd
	newNydusdPath := os.Getenv("NEW_NYDUSD_BINARY_PATH")
	if newNydusdPath == "" {
		newNydusdPath = "target/release/nydusd"
	}
	nydusdPath, err := filepath.Abs("../" + newNydusdPath)
	require.NoErrorf(t, err, "get the abs path of new nydusd path (%s)", newNydusdPath)
	err = os.Chmod(nydusdPath, 0755)
	require.NoErrorf(t, err, "chmod nydusd binary file (%s)", nydusdPath)

	upgradeReq := &tool.UpgradeRequest{
		NydusdPath: nydusdPath,
		Version:    getNydusdVersion(nydusdPath),
		Policy:     "rolling",
	}
	err = f.snapshotterCli.Upgrade(upgradeReq)
	require.NoError(t, err, "call the snapshotter to upgrade nydus daemons")

	// wait for the nydus daemons recover
	time.Sleep(5 * time.Second)

	// check the container by requesting its wait url
	runArgs := tool.GetRunArgs(t, imageName)
	resp, err := http.Get(runArgs.WaitURL)
	require.NoError(t, err, "access to the wait url of the recoverd container")
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("Failed to access the wait url of the recoverd container")
	}
}

func getNydusdVersion(nydusdPath string) string {
	versionOutput := tool.RunWithOutput(fmt.Sprintf("%s --version", nydusdPath))
	lines := strings.Split(versionOutput, "\n")
	version := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			fields := strings.Fields(line)
			version = strings.TrimSpace(fields[1])
		}
	}
	return version
}

func TestTakeover(t *testing.T) {
	if v, ok := os.LookupEnv("TAKEOVER_TEST"); !ok || v != "true" {
		t.Skip("skipping takeover test")
	}
	snapshotter = os.Getenv("SNAPSHOTTER")
	if snapshotter == "" {
		snapshotter = defaultSnapshotter
	}
	takeoverTestImage = os.Getenv("TAKEOVER_TEST_IMAGE")
	if takeoverTestImage == "" {
		takeoverTestImage = "wordpress"
	}
	snapshotterSystemSock = os.Getenv("SNAPSHOTTER_SYSTEM_SOCK")
	if snapshotterSystemSock == "" {
		snapshotterSystemSock = defaultSnapshotterSystemSock
	}
	suite := NewTakeoverTestSuit(t)
	defer suite.clear()

	test.Run(t, suite, test.Sync)
}
