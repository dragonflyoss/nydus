// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"os"
	"testing"
)

const (
	defaultSnapshotter           = "nydus"
	defaultSnapshotterSystemSock = "/run/containerd-nydus/system.sock"
)

func TestMain(m *testing.M) {
	// registryPort := os.Getenv("REGISTRY_PORT")
	// if registryPort == "" {
	// 	registryPort = "5077"
	// 	os.Setenv("REGISTRY_PORT", registryPort)
	// }
	// reg := tool.NewRegistry()
	code := m.Run()
	// reg.Destroy()
	os.Exit(code)
}
