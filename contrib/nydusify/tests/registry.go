// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var registryPort = 5051

func run(t *testing.T, cmd string, ignoreStatus bool) {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stdout = os.Stdout
	_cmd.Stderr = os.Stderr
	err := _cmd.Run()
	if !ignoreStatus {
		assert.Nil(t, err)
	}
}

func runWithOutput(t *testing.T, cmd string) string {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stderr = os.Stderr
	output, err := _cmd.Output()
	assert.Nil(t, err)
	return string(output)
}

type Registry struct {
	id   string
	host string
}

func NewRegistry(t *testing.T) *Registry {
	containerID := runWithOutput(t, fmt.Sprintf("docker run -p %d:5000 --rm -d registry:2", registryPort))
	time.Sleep(time.Second * 2)
	return &Registry{
		id:   containerID,
		host: fmt.Sprintf("localhost:%d", registryPort),
	}
}

func (registry *Registry) Destory(t *testing.T) {
	run(t, fmt.Sprintf("docker rm -f %s", registry.id), true)
}

func (registry *Registry) Build(t *testing.T, source string) {
	run(t, fmt.Sprintf("docker rmi -f %s/%s", registry.Host(), source), true)
	run(t, fmt.Sprintf("docker build -t %s/%s ./texture/%s", registry.Host(), source, source), false)
	run(t, fmt.Sprintf("docker push %s/%s", registry.Host(), source), false)
}

func (registry *Registry) Host() string {
	return registry.host
}
