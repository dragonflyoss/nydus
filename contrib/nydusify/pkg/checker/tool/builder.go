// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"io"
	"os"
	"os/exec"
)

type BuilderOption struct {
	BootstrapPath   string
	DebugOutputPath string
}

type Builder struct {
	binaryPath string
	stdout     io.Writer
	stderr     io.Writer
}

func NewBuilder(binaryPath string) *Builder {
	return &Builder{
		binaryPath: binaryPath,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
	}
}

// Check calls `nydus-image check` to parse Nydus bootstrap
// and output debug information to specified JSON file.
func (builder *Builder) Check(option BuilderOption) error {
	args := []string{
		"check",
		"--log-level",
		"warn",
		"--output-json",
		option.DebugOutputPath,
		"--bootstrap",
		option.BootstrapPath,
	}

	cmd := exec.Command(builder.binaryPath, args...)
	cmd.Stdout = builder.stdout
	cmd.Stderr = builder.stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
