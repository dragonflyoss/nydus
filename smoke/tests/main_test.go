// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
)

const (
	defaultSnapshotter           = "nydus"
	defaultSnapshotterSystemSock = "/run/containerd-nydus/system.sock"
)

func TestMain(m *testing.M) {
	registryPort := os.Getenv("REGISTRY_PORT")
	if registryPort == "" {
		registryPort = "5077"
		os.Setenv("REGISTRY_PORT", registryPort)
	}
	if os.Getenv("DISABLE_REGISTRY") == "" {
		reg := tool.NewRegistry()
		defer reg.Destroy()
	}
	code := m.Run()
	os.Exit(code)
}
