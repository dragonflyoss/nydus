// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package nydus

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type Option struct {
	ParentBootstrapPath string
	BootstrapPath       string
	BlobPath            string
	RootfsPath          string
	BackendType         string
	BackendConfig       string
	PrefetchDir         string
}

type Builder struct {
	BinaryPath string
	Stdout     io.Writer
	Stderr     io.Writer
}

func NewBuilder(binaryPath string) *Builder {
	return &Builder{
		BinaryPath: binaryPath,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
}

func (builder *Builder) Run(option Option) error {
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
		"info")

	if option.BlobPath != "" {
		args = append(args, "--blob", option.BlobPath)
	}

	if option.PrefetchDir != "" {
		option.PrefetchDir = filepath.Join(option.RootfsPath, option.PrefetchDir)
		args = append(args, "--prefetch-policy", "fs")
	}

	cmd := exec.Command(builder.BinaryPath, args...)
	cmd.Stdout = builder.Stdout
	cmd.Stderr = builder.Stderr

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
