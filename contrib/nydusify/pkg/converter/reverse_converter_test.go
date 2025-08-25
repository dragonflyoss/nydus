// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestReverseConvert(t *testing.T) {
	t.Run("Test basic reverse conversion", func(t *testing.T) {
		opt := ReverseOpt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			SourceInsecure: true,
			TargetInsecure: true,
			Platforms:      "linux/amd64",
			PushRetryCount: 3,
			PushRetryDelay: "5s",
		}

		// This test would require actual registry and nydus-image binary
		// For now, just test that the function can be called
		err := ReverseConvert(context.Background(), opt)
		// We expect an error since we don't have actual registry setup
		assert.Error(t, err)
	})
}

func TestIsNydusLayer(t *testing.T) {
	tests := []struct {
		name     string
		layer    ocispec.Descriptor
		expected bool
	}{
		{
			name: "Nydus bootstrap layer",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					"containerd.io/snapshot/nydus-bootstrap": "true",
				},
			},
			expected: true,
		},
		{
			name: "Nydus blob layer",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					"containerd.io/snapshot/nydus-blob": "true",
				},
			},
			expected: true,
		},
		{
			name: "Regular OCI layer",
			layer: ocispec.Descriptor{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			},
			expected: false,
		},
		{
			name: "Nydus media type",
			layer: ocispec.Descriptor{
				MediaType: "application/vnd.oci.image.layer.nydus.blob.v1",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNydusLayer(tt.layer)
			assert.Equal(t, tt.expected, result)
		})
	}
}