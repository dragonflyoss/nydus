// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
package cache

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"contrib/nydusify/converter"
	"contrib/nydusify/remote"
)

func run(t *testing.T, cmd string, ignoreStatus bool) {
	_cmd := exec.Command("sh", "-c", cmd)
	output, err := _cmd.CombinedOutput()
	if !ignoreStatus {
		assert.Nil(t, err)
	}
	t.Log(string(output))
}

func before(t *testing.T) {
	run(t, "docker rm -f registry", true)
	run(t, "docker run -d -p 5000:5000 --name registry registry:2.7.1", false)
	time.Sleep(time.Second * 2)
	run(t, "docker tag registry:2.7.1 localhost:5000/registry:2", false)
	run(t, "docker push localhost:5000/registry:2", false)
}

func after(t *testing.T) {
	run(t, "docker rm -f registry", true)
}

func assertImage(t *testing.T, ref string, expected string) {
	remote, err := remote.NewRemote(remote.RemoteOpt{
		Ref:      "localhost:5000/" + ref,
		Insecure: true,
	})
	assert.Nil(t, err)

	ctx := context.Background()
	manifestDesc, err := remote.Resolve(ctx)
	assert.Nil(t, err)
	assert.Equal(t, ocispec.MediaTypeImageManifest, manifestDesc.MediaType)

	manifestReader, err := remote.Pull(ctx, *manifestDesc, true)
	assert.Nil(t, err)
	manifestBytes, err := ioutil.ReadAll(manifestReader)
	assert.Nil(t, err)

	actualManifest := ocispec.Manifest{}
	err = json.Unmarshal(manifestBytes, &actualManifest)
	assert.Nil(t, err)

	// data, err := json.MarshalIndent(actualManifest, "", "  ")
	// assert.Nil(t, err)
	// err = ioutil.WriteFile(expected, []byte(string(data)+"\n"), 0644)
	// assert.Nil(t, err)

	expectedManifestBytes, err := ioutil.ReadFile(expected)
	expectedManifest := ocispec.Manifest{}
	err = json.Unmarshal(expectedManifestBytes, &expectedManifest)
	assert.Nil(t, err)

	assert.Equal(t, expectedManifest, actualManifest)
}

func convert(t *testing.T, source, target, cache string, oss bool) {
	assert.NotEmpty(
		t, os.Getenv("NYDUS_IMAGE"), "Please specify nydus-image path by env NYDUS_IMAGE",
	)

	if cache != "" {
		cache = "localhost:5000/" + cache
	}

	opt := converter.Option{
		Source:         "localhost:5000/" + source,
		Target:         "localhost:5000/" + target,
		SourceInsecure: false,
		TargetInsecure: false,
		WorkDir:        "./tmp",

		NydusImagePath: os.Getenv("NYDUS_IMAGE"),
		MultiPlatform:  false,
		DockerV2Format: false,
		BackendType:    "registry",

		BuildCache:           cache,
		BuildCacheInsecure:   false,
		BuildCacheMaxRecords: 200,
	}

	if oss {
		opt.BackendType = "oss"
		opt.BackendConfig = os.Getenv("BACKEND_CONFIG")
	}

	c, err := converter.New(opt)
	assert.Nil(t, err)

	err = c.Convert()
	assert.Nil(t, err)
}

func TestConvertWithoutCache(t *testing.T) {
	before(t)
	defer after(t)

	convert(t, "registry:2", "registry:2-nydus", "", false)
	assertImage(t, "registry:2-nydus", "./texture/image0/manifest.json")
}

func TestConvertWithCache(t *testing.T) {
	before(t)
	defer after(t)

	convert(t, "registry:2", "registry:2-nydus", "cache:v1", false)
	assertImage(t, "registry:2-nydus", "./texture/image0/manifest.json")
	assertImage(t, "cache:v1", "./texture/image0/cache.json")

	convert(t, "registry:2", "registry:2-nydus", "cache:v1", false)
	assertImage(t, "registry:2-nydus", "./texture/image0/manifest.json")
	assertImage(t, "cache:v1", "./texture/image0/cache.json")

	run(t, "docker build -t localhost:5000/registry:2-image1 ./texture/image1", false)
	run(t, "docker push localhost:5000/registry:2-image1", false)
	convert(t, "registry:2-image1", "registry:2-image1-nydus", "cache:v1", false)
	assertImage(t, "registry:2-image1-nydus", "./texture/image1/manifest.json")
	assertImage(t, "cache:v1", "./texture/image1/cache.json")

	convert(t, "registry:2-image1", "registry:2-image1-nydus", "cache:v1", false)
	assertImage(t, "registry:2-image1-nydus", "./texture/image1/manifest.json")
	assertImage(t, "cache:v1", "./texture/image1/cache.json")

	run(t, "docker build -t localhost:5000/registry:2-image2 ./texture/image2", false)
	run(t, "docker push localhost:5000/registry:2-image2", false)
	convert(t, "registry:2-image2", "registry:2-image2-nydus", "cache:v1", false)
	assertImage(t, "registry:2-image2-nydus", "./texture/image2/manifest.json")
	assertImage(t, "cache:v1", "./texture/image2/cache.json")

	run(t, "docker build -t localhost:5000/registry:2-image3 ./texture/image3", false)
	run(t, "docker push localhost:5000/registry:2-image3", false)
	convert(t, "registry:2-image3", "registry:2-image3-nydus", "cache:v1", false)
	assertImage(t, "registry:2-image3-nydus", "./texture/image3/manifest.json")
	assertImage(t, "cache:v1", "./texture/image3/cache.json")
}

func TestConvertWithOSSBackend(t *testing.T) {
	if os.Getenv("BACKEND_CONFIG") == "" {
		return
	}

	before(t)
	defer after(t)

	convert(t, "registry:2", "registry:2-image4-nydus", "cache:v1", true)
	assertImage(t, "registry:2-image4-nydus", "./texture/image4/manifest.json")
	assertImage(t, "cache:v1", "./texture/image0/cache.json")

	convert(t, "registry:2", "registry:2-image4-nydus", "cache:v1", true)
	assertImage(t, "registry:2-image4-nydus", "./texture/image4/manifest.json")
	assertImage(t, "cache:v1", "./texture/image0/cache.json")
}
