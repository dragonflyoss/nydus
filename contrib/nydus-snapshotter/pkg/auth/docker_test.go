/*
 * Copyright (c) 2021. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testConfigFmt = `
{
        "auths": {
                "%s": {
                        "auth": "%s"
                },
                "%s": {
                        "auth": "%s"
                }
        }
}
`
	dockerUser = "dockeruserfoobar"
	dockerPass = "dockerpassfoobar"
	extraHost  = "reg.docker.alibaba-cloud.com"
	extraUser  = "extrauserfoobar"
	extraPass  = "extrapassfoobar"

	configFile = "config.json"
)

var oldDockerConfig = os.Getenv("DOCKER_CONFIG")

func setupDockerConfig() (string, error) {
	dir, err := ioutil.TempDir("", "testdocker-")
	if err != nil {
		return "", err
	}
	os.Setenv("DOCKER_CONFIG", dir)

	err = ioutil.WriteFile(filepath.Join(dir, configFile),
		[]byte(fmt.Sprintf(testConfigFmt, dockerHost, base64.StdEncoding.EncodeToString([]byte(dockerUser+":"+dockerPass)),
			extraHost, base64.StdEncoding.EncodeToString([]byte(extraUser+":"+extraPass)))),
		0600)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	return dir, nil
}

func TestDockerCred(t *testing.T) {
	assert := assert.New(t)

	dir, err := setupDockerConfig()
	assert.Nil(err)
	defer func() {
		os.RemoveAll(dir)
		os.Setenv("DOCKER_CONFIG", oldDockerConfig)
	}()

	// Empty host should get empty auth
	auth := FromDockerConfig("")
	assert.Nil(auth)

	// Unmatching host should get empty auth
	auth = FromDockerConfig("foo")
	assert.Nil(auth)

	auth = FromDockerConfig(dockerHost)
	assert.NotNil(auth)
	assert.Equal(auth.Username, dockerUser)
	assert.Equal(auth.Password, dockerPass)

	auth = FromDockerConfig(convertedDockerHost)
	assert.NotNil(auth)
	assert.Equal(auth.Username, dockerUser)
	assert.Equal(auth.Password, dockerPass)

	auth = FromDockerConfig(extraHost)
	assert.NotNil(auth)
	assert.Equal(auth.Username, extraUser)
	assert.Equal(auth.Password, extraPass)
}
