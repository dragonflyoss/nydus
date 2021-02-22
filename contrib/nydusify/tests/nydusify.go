// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"contrib/nydusify/checker"
	"contrib/nydusify/converter"
)

var nydusImagePath string
var nydusdPath string

func init() {
	nydusImagePath = os.Getenv("NYDUS_IMAGE")
	if nydusImagePath == "" {
		panic("Please specify nydus-image path by env NYDUS_IMAGE")
	}
	nydusdPath = os.Getenv("NYDUSD")
	if nydusdPath == "" {
		panic("Please specify nydusd path by env NYDUSD")
	}
}

type Nydusify struct {
	Registry      *Registry
	Source        string
	Target        string
	Cache         string
	backendType   string
	backendConfig string
}

func NewNydusify(registry *Registry, source, target, cache string) *Nydusify {
	host := registry.Host()

	backendType := "registry"
	if os.Getenv("BACKEND_TYPE") != "" {
		backendType = os.Getenv("BACKEND_TYPE")
	}
	backendConfig := fmt.Sprintf(`{
		"host": "%s",
		"repo": "%s",
		"scheme": "http"
	}`, host, target)
	if os.Getenv("BACKEND_CONFIG") != "" {
		backendConfig = os.Getenv("BACKEND_CONFIG")
	}

	return &Nydusify{
		Registry:      registry,
		Source:        source,
		Target:        target,
		Cache:         cache,
		backendType:   backendType,
		backendConfig: backendConfig,
	}
}

func (nydusify *Nydusify) Convert(t *testing.T) {
	host := nydusify.Registry.Host()

	buildCache := ""
	if nydusify.Cache != "" {
		buildCache = host + "/" + nydusify.Cache
	}

	opt := converter.Option{
		Source:         host + "/" + nydusify.Source,
		Target:         host + "/" + nydusify.Target,
		SourceInsecure: true,
		TargetInsecure: true,
		WorkDir:        "./tmp",

		NydusImagePath: nydusImagePath,
		MultiPlatform:  false,
		DockerV2Format: true,
		BackendType:    nydusify.backendType,
		BackendConfig:  nydusify.backendConfig,

		BuildCache:           buildCache,
		BuildCacheInsecure:   true,
		BuildCacheMaxRecords: 10,
	}

	c, err := converter.New(opt)
	assert.Nil(t, err)

	err = c.Convert()
	assert.Nil(t, err)
}

func (nydusify *Nydusify) Check(t *testing.T) {
	host := nydusify.Registry.Host()

	checker, err := checker.New(checker.Opt{
		WorkDir:        filepath.Join("./tmp", nydusify.Target),
		Source:         host + "/" + nydusify.Source,
		Target:         host + "/" + nydusify.Target,
		SourceInsecure: true,
		TargetInsecure: true,
		NydusImagePath: nydusImagePath,
		NydusdPath:     nydusdPath,
		BackendType:    nydusify.backendType,
		BackendConfig:  nydusify.backendConfig,
	})
	assert.Nil(t, err)

	err = checker.Check()
	assert.Nil(t, err)
}
