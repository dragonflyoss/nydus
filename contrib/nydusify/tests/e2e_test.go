// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/stretchr/testify/require"
)

func testBasicConvert(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)
	registry.Build(t, "image-basic")
	nydusify := NewNydusify(registry, "image-basic", "image-basic-nydus", "", "", fsVersion)
	nydusify.Convert(t)
	nydusify.Check(t)
}

func testReproducableBuild(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	registry.Build(t, "image-basic")
	defer registry.Destroy(t)
	var initBootstraHash []byte
	// Build the same image repeatedly to verify that the bootstarp files are the same
	for i := 0; i < 5; i++ {
		workDir := fmt.Sprintf("./tmp-%d", i)
		os.Setenv("WORKDIR", workDir)
		nydusify := NewNydusify(registry, "image-basic", "image-basic-nydus", "", "", fsVersion)
		nydusify.Convert(t)
		nydusify.Check(t)
		hash, err := utils.HashFile(nydusify.GetBootstarpFilePath())
		if err != nil {
			t.Fatalf("expect bootstrap file must exist, but actual is not, error: %s", err)
		}
		if len(initBootstraHash) == 0 {
			initBootstraHash = hash
		} else {
			require.Equal(t, initBootstraHash, hash)
		}
	}
}

func testConvertWithCache(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)

	registry.Build(t, "image-basic")
	nydusify1 := NewNydusify(registry, "image-basic", "image-basic-nydus-1", "cache:v1", "", fsVersion)
	nydusify1.Convert(t)
	nydusify1.Check(t)
	nydusify2 := NewNydusify(registry, "image-basic", "image-basic-nydus-2", "cache:v1", "", fsVersion)
	nydusify2.Convert(t)
	nydusify2.Check(t)

	registry.Build(t, "image-from-1")
	nydusify3 := NewNydusify(registry, "image-from-1", "image-from-nydus-1", "cache:v1", "", fsVersion)
	nydusify3.Convert(t)
	nydusify3.Check(t)

	registry.Build(t, "image-from-2")
	nydusify4 := NewNydusify(registry, "image-from-2", "image-from-nydus-2", "cache:v1", "", fsVersion)
	nydusify4.Convert(t)
	nydusify4.Check(t)
}

func testConvertWithChunkDict(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)

	registry.Build(t, "chunk-dict-1")
	// build chunk-dict-1 bootstrap
	nydusify1 := NewNydusify(registry, "chunk-dict-1", "nydus:chunk-dict-1", "", "", fsVersion)
	nydusify1.Convert(t)
	nydusify1.Check(t)
	chunkDictOpt := fmt.Sprintf("bootstrap:registry:%s/%s", registry.Host(), "nydus:chunk-dict-1")
	// build without build-cache
	registry.Build(t, "image-basic")
	nydusify2 := NewNydusify(registry, "image-basic", "nydus:image-basic", "", chunkDictOpt, fsVersion)
	nydusify2.Convert(t)
	nydusify2.Check(t)
	// build with build-cache
	registry.Build(t, "image-from-1")
	nydusify3 := NewNydusify(registry, "image-from-1", "nydus:image-from-1", "nydus:cache_v1", chunkDictOpt, fsVersion)
	nydusify3.Convert(t)
	nydusify3.Check(t)
	// change chunk dict
	registry.Build(t, "chunk-dict-2")
	nydusify4 := NewNydusify(registry, "chunk-dict-2", "nydus:chunk-dict-2", "", "", fsVersion)
	nydusify4.Convert(t)
	nydusify4.Check(t)
	chunkDictOpt = fmt.Sprintf("bootstrap:registry:%s/%s", registry.Host(), "nydus:chunk-dict-2")
	registry.Build(t, "image-from-2")
	nydusify5 := NewNydusify(registry, "image-from-2", "nydus:image-from-2", "nydus:cache_v1", chunkDictOpt, fsVersion)
	nydusify5.Convert(t)
	nydusify5.Check(t)
}

func TestSmoke(t *testing.T) {
	fsVersions := [2]string{"5", "6"}
	for _, v := range fsVersions {
		testBasicConvert(t, v)
		testReproducableBuild(t, v)
		testConvertWithCache(t, v)
		testConvertWithChunkDict(t, v)
	}
}
