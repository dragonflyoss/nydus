// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
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

	logger, err := provider.DefaultLogger()
	assert.Nil(t, err)

	workDir := "./tmp"
	sourceDir := filepath.Join(workDir, "source")
	err = os.MkdirAll(sourceDir, 0755)
	assert.Nil(t, err)

	sourceRemote, err := provider.DefaultRemote(host+"/"+nydusify.Source, true)
	assert.Nil(t, err)

	sourceProviders, err := provider.DefaultSource(context.Background(), sourceRemote, sourceDir, "linux/amd64")
	assert.Nil(t, err)

	targetRemote, err := provider.DefaultRemote(host+"/"+nydusify.Target, true)
	assert.Nil(t, err)

	var cacheRemote *remote.Remote
	if buildCache != "" {
		buildCache = host + "/" + nydusify.Cache
		cacheRemote, err = provider.DefaultRemote(buildCache, true)
		assert.Nil(t, err)
	}

	opt := converter.Opt{
		Logger:          logger,
		SourceProviders: sourceProviders,

		TargetRemote: targetRemote,

		CacheRemote:     cacheRemote,
		CacheMaxRecords: 10,
		CacheVersion:    "v1",

		WorkDir:        "./tmp",
		PrefetchDir:    "/",
		NydusImagePath: nydusImagePath,
		MultiPlatform:  false,
		DockerV2Format: true,

		BackendType:   nydusify.backendType,
		BackendConfig: nydusify.backendConfig,
	}

	cvt, err := converter.New(opt)
	assert.Nil(t, err)

	err = cvt.Convert(context.Background())
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
		ExpectedArch:   "amd64",
	})
	assert.Nil(t, err)

	err = checker.Check(context.Background())
	assert.Nil(t, err)
}
