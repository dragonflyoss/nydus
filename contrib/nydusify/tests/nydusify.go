// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter"
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
	chunkDictArgs string
	fsVersion     string
	workDir       string
}

func NewNydusify(registry *Registry, source, target, cache string, chunkDictArgs string, fsVersion string) *Nydusify {
	backendType := ""
	if os.Getenv("BACKEND_TYPE") != "" {
		backendType = os.Getenv("BACKEND_TYPE")
	}
	backendConfig := ""
	if os.Getenv("BACKEND_CONFIG") != "" {
		backendConfig = os.Getenv("BACKEND_CONFIG")
	}
	if len(fsVersion) == 0 {
		fsVersion = "5"
	}

	workDir := "./tmp"
	if os.Getenv("WORKDIR") != "" {
		workDir = os.Getenv("WORKDIR")
	}

	return &Nydusify{
		Registry:      registry,
		Source:        source,
		Target:        target,
		Cache:         cache,
		backendType:   backendType,
		backendConfig: backendConfig,
		chunkDictArgs: chunkDictArgs,
		fsVersion:     fsVersion,
		workDir:       workDir,
	}
}

func (nydusify *Nydusify) GetBootstarpFilePath() string {
	return filepath.Join(filepath.Join(nydusify.workDir, nydusify.Target), "nydus_bootstrap")
}

func (nydusify *Nydusify) Convert(t *testing.T) {
	host := nydusify.Registry.Host()
	buildCache := ""
	if nydusify.Cache != "" {
		buildCache = host + "/" + nydusify.Cache
	}

	opt := converter.Opt{
		Platforms: "linux/amd64",
		Source:    host + "/" + nydusify.Source,
		Target:    host + "/" + nydusify.Target,

		CacheRef:        buildCache,
		CacheMaxRecords: 10,
		CacheVersion:    "v1",

		WorkDir:          nydusify.workDir,
		PrefetchPatterns: "/",
		NydusImagePath:   nydusImagePath,
		MergePlatform:    false,
		Docker2OCI:       true,

		BackendType:   nydusify.backendType,
		BackendConfig: nydusify.backendConfig,

		FsVersion: nydusify.fsVersion,
	}

	err := converter.Convert(context.Background(), opt)
	assert.Nil(t, err)
}

func (nydusify *Nydusify) Check(t *testing.T) {
	host := nydusify.Registry.Host()
	logrus.Infof("the backend type used by 'nydusify check': %s", nydusify.backendType)
	logrus.Infof("the backend config used by 'nydusify check': %s", nydusify.backendConfig)
	checker, err := checker.New(checker.Opt{
		WorkDir:        filepath.Join(nydusify.workDir, nydusify.Target),
		Source:         host + "/" + nydusify.Source,
		Target:         host + "/" + nydusify.Target,
		SourceInsecure: true,
		TargetInsecure: true,
		NydusImagePath: nydusImagePath,
		NydusdPath:     nydusdPath,
		ExpectedArch:   "amd64",
		BackendType:    nydusify.backendType,
		BackendConfig:  nydusify.backendConfig,
	})
	assert.Nil(t, err)

	err = checker.Check(context.Background())
	assert.Nil(t, err)
}
