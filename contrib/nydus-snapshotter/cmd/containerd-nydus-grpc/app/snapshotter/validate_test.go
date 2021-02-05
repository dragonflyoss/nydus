/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshotter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"contrib/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/command"
)

func TestValidate(t *testing.T) {
	var cfg Config
	err := Validate(&command.Args{
		ValidateSignature: false,
		RootDir: "/root",
		Address: "/root/rpc",
		ConfigPath: "testdata/happypath/config.json",
		LogLevel: "debug",
	}, &cfg)
	assert.Nil(t, err)
	assert.Equal(t, "direct", cfg.DaemonCfg.Mode)
}

func TestValidate_ConfigFile_NotExists(t *testing.T) {
	var cfg Config
	err := Validate(&command.Args{
		ValidateSignature: false,
		RootDir: "/root",
		Address: "/root/rpc",
		ConfigPath: "testdata/happypath/notexists.json",
		LogLevel: "debug",
	}, &cfg)
	assert.NotNil(t, err)
}
