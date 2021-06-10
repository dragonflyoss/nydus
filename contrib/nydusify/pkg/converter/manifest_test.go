// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"strings"
	"testing"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func makePlatform(osArch string, nydus bool) *ocispec.Platform {
	var platform *ocispec.Platform
	if osArch == "" {
		platform = &ocispec.Platform{
			OS:           "",
			Architecture: "",
		}
	} else {
		platform = &ocispec.Platform{
			OS:           strings.Split(osArch, "/")[0],
			Architecture: strings.Split(osArch, "/")[1],
		}
	}
	if nydus {
		platform.OSFeatures = []string{utils.ManifestOSFeatureNydus}
	}
	return platform
}

func makeDesc(id string, platform *ocispec.Platform) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("manifest-" + id),
		Size:      10,
		Platform:  platform,
	}
}

func TestManifest(t *testing.T) {
	mm := manifestManager{
		multiPlatform:  true,
		dockerV2Format: false,
	}

	nydusDesc := makeDesc("nydus", makePlatform("linux/amd64", true))

	// Merge with existing OCI manifests
	existDescs := []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("2", makePlatform("linux/ppc64le", false)),
	}
	index, err := mm.makeManifestIndex(context.Background(), existDescs, &nydusDesc, nil)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("2", makePlatform("linux/ppc64le", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	existDescs = []ocispec.Descriptor{
		makeDesc("1", makePlatform("", false)),
	}
	index, err = mm.makeManifestIndex(context.Background(), existDescs, &nydusDesc, nil)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	existDescs = []ocispec.Descriptor{
		makeDesc("1", nil),
	}
	index, err = mm.makeManifestIndex(context.Background(), existDescs, &nydusDesc, nil)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	// Merge with specified OCI manifest
	ociDesc := makeDesc("1", makePlatform("linux/amd64", false))
	index, err = mm.makeManifestIndex(context.Background(), nil, &nydusDesc, &ociDesc)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	ociDesc = makeDesc("1", nil)
	index, err = mm.makeManifestIndex(context.Background(), nil, &nydusDesc, &ociDesc)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	ociDesc = makeDesc("1", makePlatform("", false))
	index, err = mm.makeManifestIndex(context.Background(), nil, &nydusDesc, &ociDesc)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	// Preferred to merge with existing OCI manifests, instead of specified OCI manifest
	ociDesc = makeDesc("3", makePlatform("linux/amd64", false))
	existDescs = []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("2", makePlatform("linux/ppc64le", false)),
	}
	index, err = mm.makeManifestIndex(context.Background(), existDescs, &nydusDesc, &ociDesc)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("2", makePlatform("linux/ppc64le", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)

	ociDesc = makeDesc("3", makePlatform("linux/amd64", false))
	existDescs = []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
		makeDesc("2", makePlatform("linux/ppc64le", false)),
	}
	index, err = mm.makeManifestIndex(context.Background(), existDescs, &nydusDesc, &ociDesc)
	assert.Nil(t, err)
	assert.Equal(t, []ocispec.Descriptor{
		makeDesc("1", makePlatform("linux/amd64", false)),
		makeDesc("2", makePlatform("linux/ppc64le", false)),
		makeDesc("nydus", makePlatform("linux/amd64", true)),
	}, index.Manifests)
}
