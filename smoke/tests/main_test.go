// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"log"
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

	var reg *tool.Registry
	if os.Getenv("DISABLE_REGISTRY") == "" {
		reg = tool.NewRegistry()
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.SetOutput(os.Stderr)

	code := m.Run()

	if reg != nil {
		reg.Destroy()
	}
	os.Exit(code)
}
