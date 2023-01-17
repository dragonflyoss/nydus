// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Run(t *testing.T, cmd string) {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stdout = os.Stdout
	_cmd.Stderr = os.Stderr
	err := _cmd.Run()
	assert.Nil(t, err)
}

func RunWithOutput(cmd string) string {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stderr = os.Stderr

	output, err := _cmd.Output()
	if err != nil {
		panic(err)
	}

	return string(output)
}

func GetBinaries(t *testing.T) (string, string, string) {
	builderPath := os.Getenv("NYDUS_BUILDER")
	if builderPath == "" {
		builderPath = "nydus-image"
	}

	nydusdPath := os.Getenv("NYDUS_NYDUSD")
	if nydusdPath == "" {
		nydusdPath = "nydusd"
	}

	nydusifyPath := os.Getenv("NYDUS_NYDUSIFY")
	if nydusifyPath == "" {
		nydusifyPath = "nydusify"
	}

	return builderPath, nydusdPath, nydusifyPath
}
