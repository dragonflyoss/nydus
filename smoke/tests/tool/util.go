// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var defaultBinary = map[string]string{
	"NYDUS_BUILDER":  "nydus-image",
	"NYDUS_NYDUSD":   "nydusd",
	"NYDUS_NYDUSIFY": "nydusify",
}

func RunWithCombinedOutput(cmd string) (string, error) {
	_cmd := exec.Command("sh", "-c", cmd)
	output, err := _cmd.CombinedOutput()

	return string(output), err
}

func Run(t *testing.T, cmd string) {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stdout = os.Stdout
	_cmd.Stderr = os.Stderr
	err := _cmd.Run()
	assert.Nil(t, err)
}

func RunWithoutOutput(t *testing.T, cmd string) {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stdout = io.Discard
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

func GetBinary(t *testing.T, env, version string) string {
	version = strings.ReplaceAll(version, ".", "_")
	key := fmt.Sprintf("%s_%s", env, version)
	if version == "latest" && os.Getenv(key) == "" {
		key = env
	}
	binary := os.Getenv(key)
	if binary == "" {
		if version == "latest" && defaultBinary[env] != "" {
			return defaultBinary[env]
		}
		t.Fatalf("not found binary from env `%s`, version %s", env, version)
	}
	return binary
}
