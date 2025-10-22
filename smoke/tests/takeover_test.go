// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nydus-snapshotter/config"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshotter, nydusd.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.

const (
	hotUpgradeRepeatCount = 6
	configPath            = "/etc/nydus/config.toml"
)

var (
	snapshotter           string
	takeoverTestImage     string
	snapshotterSystemSock string
	nydusdPaths           []string
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

func (f *TakeoverTestSuit) rmContainer(containerName string) {
	tool.RunWithoutOutput(f.t, fmt.Sprintf("sudo nerdctl --snapshotter %s rm -f %s", snapshotter, containerName))
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
	checkContainerAccess(t, imageName)
}

func (f *TakeoverTestSuit) TestRestartSnapshotterHotUpgrade(t *testing.T) {
	imageName := f.testImage

	containerName := uuid.NewString()
	tool.RunContainerSimple(t, imageName, snapshotter, containerName, false)
	defer f.rmContainer(containerName)

	// restart snapshotter trigger hot upgrade nydusd
	for i := 0; i < hotUpgradeRepeatCount; i++ {
		nydusdPath := nydusdPaths[i%2]
		logrus.Debugf("Restart hot upgrade round %d, nydusd_path = %s", i+1, nydusdPath)

		setNydusdPathInConfig(t, nydusdPath)

		cmd := exec.Command("sudo", "systemctl", "restart", "nydus-snapshotter")
		err := cmd.Run()
		require.NoError(t, err, "restart nydus-snapshotter")

		// wait for the nydus daemons recover
		time.Sleep(5 * time.Second)

		// check the container by requesting its wait url
		checkContainerAccess(t, imageName)
	}
}

func (f *TakeoverTestSuit) TestAPIHotUpgrade(t *testing.T) {
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
	require.NoError(t, err, "access to the wait url of the recovered container")
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("Failed to access the wait url of the recovered container")
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

func setNydusdPathInConfig(t *testing.T, newNydusdPath string) {
	data, err := os.ReadFile(configPath)
	require.NoError(t, err, "read snapshotter config.toml")

	cfg := &config.SnapshotterConfig{}
	err = toml.Unmarshal(data, cfg)
	require.NoError(t, err, "unmarshal snapshotter config.toml")

	cfg.DaemonConfig.NydusdPath = newNydusdPath

	newData, err := toml.Marshal(cfg)
	require.NoError(t, err, "marshal config.toml")

	err = os.WriteFile(configPath, newData, 0644)
	require.NoError(t, err, "write config.toml")
}

func checkContainerAccess(t *testing.T, imageName string) {
	runArgs := tool.GetRunArgs(t, imageName)
	resp, err := http.Get(runArgs.WaitURL)
	require.NoError(t, err, "access to the wait url of the recovered container")
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("Failed to access the wait url of the recovered container")
	}
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
	newNydusdPath := os.Getenv("NEW_NYDUSD_BINARY_PATH")
	if newNydusdPath == "" {
		newNydusdPath = "target/release/nydusd"
	}
	absNewNydusdPath, err := filepath.Abs("../" + newNydusdPath)
	require.NoErrorf(t, err, "get the abs path of new nydusd path (%s)", newNydusdPath)
	err = os.Chmod(absNewNydusdPath, 0755)
	require.NoErrorf(t, err, "chmod nydusd binary file (%s)", absNewNydusdPath)

	nydusdPaths = []string{
		absNewNydusdPath,
		"/usr/local/bin/nydusd",
	}
	suite := NewTakeoverTestSuit(t)
	defer suite.clear()

	test.Run(t, suite, test.Sync)
}
