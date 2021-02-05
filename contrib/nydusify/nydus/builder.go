// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package nydus

import (
	"io"
	"os"
	"os/exec"
)

type BuilderOption struct {
	ParentBootstrapPath string
	BootstrapPath       string
	BlobPath            string
	RootfsPath          string
	BackendType         string
	BackendConfig       string
	PrefetchDir         string
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

func (builder *Builder) Run(option BuilderOption) error {
	var args []string
	if option.ParentBootstrapPath == "" {
		args = []string{
			"create",
		}
	} else {
		args = []string{
			"create",
			"--parent-bootstrap",
			option.ParentBootstrapPath,
		}
	}
	args = append(
		args,
		"--bootstrap",
		option.BootstrapPath,
		"--backend-type",
		option.BackendType,
		"--backend-config",
		option.BackendConfig,
		option.RootfsPath,
		"--log-level",
		"warn")

	if option.BlobPath != "" {
		args = append(args, "--blob", option.BlobPath)
	}

	if option.PrefetchDir != "" {
		args = append(args, "--prefetch-policy", "fs")
	}

	cmd := exec.Command(builder.binaryPath, args...)
	cmd.Stdout = builder.stdout
	cmd.Stderr = builder.stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	io.WriteString(stdin, option.PrefetchDir)
	stdin.Close()

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
