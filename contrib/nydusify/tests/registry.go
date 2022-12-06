// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	id         string
	host       string
	authFile   string
	authString string // base64(username:password)
	configFile string
}

func NewAuthRegistry(t *testing.T) *Registry {
	err := os.Mkdir("auth", 0755)
	assert.Nil(t, err)
	authString := runWithOutput(t, "docker run --rm --entrypoint htpasswd httpd:2 -Bbn testuser testpassword")
	authFile, _ := filepath.Abs(filepath.Join("auth", "htpasswd"))
	err = ioutil.WriteFile(authFile, []byte(authString), 0644)
	assert.Nil(t, err)

	err = os.Mkdir(".docker", 0755)
	assert.Nil(t, err)
	base64AuthString := base64.StdEncoding.EncodeToString([]byte("testuser:testpassword"))
	configString := fmt.Sprintf(`{"auths": { "localhost:%d": { "auth": "%s" }}}`,
		registryPort, base64AuthString)
	configFile, _ := filepath.Abs(filepath.Join(".docker", "config.json"))
	err = os.Setenv("DOCKER_CONFIG", path.Dir(configFile))
	assert.Nil(t, err)
	err = ioutil.WriteFile(configFile, []byte(configString), 0644)
	assert.Nil(t, err)

	containerID := runWithOutput(t, fmt.Sprintf("docker run -p %d:5000 --rm -d  -v %s:/auth "+
		`-e "REGISTRY_AUTH=htpasswd" -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" `+
		"-e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd registry:2", registryPort, path.Dir(authFile)))
	time.Sleep(time.Second * 2)

	return &Registry{
		id:         containerID,
		host:       fmt.Sprintf("localhost:%d", registryPort),
		authFile:   authFile,
		authString: base64AuthString,
		configFile: configFile,
	}
}

func NewRegistry(t *testing.T) *Registry {
	containerID := runWithOutput(t, fmt.Sprintf("docker run -p %d:5000 -d registry:2", registryPort))
	time.Sleep(time.Second * 2)
	return &Registry{
		id:   containerID,
		host: fmt.Sprintf("localhost:%d", registryPort),
	}
}

func (registry *Registry) Destroy(t *testing.T) {
	run(t, fmt.Sprintf("docker stop  %s", registry.id), true)
	run(t, fmt.Sprintf("docker rm -f  %s", registry.id), true)
	if registry.authFile != "" {
		os.RemoveAll(path.Dir(registry.authFile))
	}
	if registry.configFile != "" {
		os.RemoveAll(path.Dir(registry.configFile))
	}
}

func (registry *Registry) Build(t *testing.T, source string) {
	run(t, fmt.Sprintf("docker rmi -f %s/%s", registry.Host(), source), true)
	run(t, fmt.Sprintf("docker build -t %s/%s ./texture/%s", registry.Host(), source, source), false)
	run(t, fmt.Sprintf("docker push %s/%s", registry.Host(), source), false)
}

func (registry *Registry) AuthBuild(t *testing.T, source string) {
	run(t, fmt.Sprintf("docker rmi -f %s/%s", registry.Host(), source), true)
	run(t, fmt.Sprintf("docker build -t %s/%s ./texture/%s", registry.Host(), source, source), false)
	run(t, fmt.Sprintf("docker login -u testuser -p testpassword %s", registry.Host()), false)
	run(t, fmt.Sprintf("docker push %s/%s", registry.Host(), source), false)
}

func (registry *Registry) Host() string {
	return registry.host
}
