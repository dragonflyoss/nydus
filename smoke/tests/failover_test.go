// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshotter, nydusd.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.

type FailoverTestSuit struct {
	t *testing.T
}

func (f *FailoverTestSuit) TestFailover(t *testing.T) {
	// prepare the basic constants
	snapshotter := os.Getenv("SNAPSHOTTER")
	if snapshotter == "" {
		snapshotter = defaultSnapshotter
	}
	sourceImage := os.Getenv("FAILOVER_TEST_IMAGE")
	if sourceImage == "" {
		sourceImage = "wordpress"
	}
	snapshotterSystemSock := os.Getenv("SNAPSHOTTER_SYSTEM_SOCK")
	if snapshotterSystemSock == "" {
		snapshotterSystemSock = defaultSnapshotterSystemSock
	}

	ctx := tool.DefaultContext(t)

	// prepare and convert image
	sourceImage = tool.PrepareImage(t, sourceImage)
	imageName := fmt.Sprintf("%s:nydus", sourceImage)
	tool.ConvertImage(t, ctx, sourceImage, imageName)

	containerName := uuid.NewString()
	tool.RunContainerSimple(t, imageName, snapshotter, containerName, false)
	defer tool.ClearContainer(t, imageName, snapshotter, containerName)

	snapshotterCli := tool.NewSnapshotterClient(snapshotterSystemSock)
	daemons, err := snapshotterCli.GetNydusDaemonInfos()
	if err != nil {
		t.Fatalf("Failed to get nydus daemon infos: %s", err.Error())
	}

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
	if err != nil || !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		t.Fatal("Failed to access the wait url of the recoverd container")
	}
}

func TestFailover(t *testing.T) {
	if v, ok := os.LookupEnv("FAILOVER_TEST"); !ok || v != "true" {
		t.Skip("skipping failover test")
	}
	test.Run(t, &FailoverTestSuit{t: t})
}
