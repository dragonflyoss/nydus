/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestFsVersion(t *testing.T) {
	tests := []struct {
		name string
		img  *Image
		run  func(t *testing.T, version string, ok bool)
	}{
		{
			name: "nydus image with annotation",
			img: &Image{
				Kind: KindNydus,
				Bootstrap: &ocispec.Descriptor{Annotations: map[string]string{
					nydus.LayerAnnotationNydusFsVersion: nydus.NydusFsVersion,
				}},
			},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(nydus.NydusFsVersion, version)
			},
		},
		{
			name: "nydus image without annotation",
			img:  &Image{Kind: KindNydus, Bootstrap: &ocispec.Descriptor{}},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(nydus.NydusFsVersionUnknown, version)
			},
		},
		{
			name: "nydus image without bootstrap",
			img:  &Image{Kind: KindNydus},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(version)
			},
		},
		{
			name: "oci image",
			img:  &Image{Kind: KindOCI},
			run: func(t *testing.T, version string, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(version)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version, ok := tc.img.FsVersion()
			tc.run(t, version, ok)
		})
	}
}
