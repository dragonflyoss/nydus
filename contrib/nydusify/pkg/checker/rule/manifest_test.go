// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/stretchr/testify/require"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestManifestName(t *testing.T) {
	rule := ManifestRule{}
	require.Equal(t, "Manifest", rule.Name())
}

func TestManifestRuleValidate_IgnoreDeprecatedField(t *testing.T) {
	source := &parser.Parsed{
		OCIImage: &parser.Image{
			Config: ocispec.Image{
				Config: ocispec.ImageConfig{
					ArgsEscaped: true, // deprecated field
				},
			},
		},
	}
	target := &parser.Parsed{
		NydusImage: &parser.Image{
			Config: ocispec.Image{
				Config: ocispec.ImageConfig{
					ArgsEscaped: false,
				},
			},
		},
	}

	rule := ManifestRule{
		SourceParsed: source,
		TargetParsed: target,
	}

	require.Nil(t, rule.Validate())
}

func TestManifestRuleValidate_MultiPlatform(t *testing.T) {
	source := &parser.Parsed{
		OCIImage: &parser.Image{},
	}
	target := &parser.Parsed{
		NydusImage: &parser.Image{},
	}

	rule := ManifestRule{
		MultiPlatform: true,
		ExpectedArch:  "amd64",
		SourceParsed:  source,
		TargetParsed:  target,
	}
	require.Error(t, rule.Validate())
	require.Contains(t, rule.Validate().Error(), "not found image manifest list")

	rule.TargetParsed.Index = &ocispec.Index{}
	require.Error(t, rule.Validate())
	require.Contains(t, rule.Validate().Error(), "not found nydus image of specified platform linux")

	rule.TargetParsed.Index = &ocispec.Index{
		Manifests: []ocispec.Descriptor{
			{
				MediaType: utils.MediaTypeNydusBlob,
				Platform: &ocispec.Platform{
					Architecture: "amd64",
					OS:           "linux",
					OSFeatures:   []string{utils.ManifestOSFeatureNydus},
				},
			},
		},
	}
	require.Error(t, rule.Validate())
	require.Contains(t, rule.Validate().Error(), "not found OCI image of specified platform linux")

	rule.TargetParsed.Index.Manifests = append(rule.TargetParsed.Index.Manifests, ocispec.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Platform: &ocispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
	})
	require.NoError(t, rule.Validate())
}

func TestManifestRuleValidate_TargetLayer(t *testing.T) {
	rule := ManifestRule{
		SourceParsed: &parser.Parsed{},
		TargetParsed: &parser.Parsed{},
	}
	require.Error(t, rule.Validate())
	require.Contains(t, rule.Validate().Error(), "invalid nydus image manifest")

	rule.TargetParsed = &parser.Parsed{
		NydusImage: &parser.Image{
			Manifest: ocispec.Manifest{
				MediaType: "application/vnd.docker.distribution.manifest.v2+json",
				Config: ocispec.Descriptor{
					MediaType: "application/vnd.oci.image.config.v1+json",
					Digest:    "sha256:563fad1f51cec2ee4c972af4bfd7275914061e2f73770585cfb04309cb5e0d6b",
					Size:      523,
				},
				Layers: []ocispec.Descriptor{
					{
						MediaType: "application / vnd.oci.image.layer.v1.tar",
						Digest:    "sha256:09845cce1d983b158d4865fc37c23bbfb892d4775c786e8114d3cf868975c059",
						Size:      83528010,
						Annotations: map[string]string{
							"containerd.io/snapshot/nydus-blob": "true",
						},
					},
					{
						MediaType: "application/vnd.oci.image.layer.nydus.blob.v1",
						Digest:    "sha256:09845cce1d983b158d4865fc37c23bbfb892d4775c786e8114d3cf868975c059",
						Size:      83528010,
						Annotations: map[string]string{
							"containerd.io/snapshot/nydus-blob": "true",
						},
					},
				},
			},
		},
	}
	require.Error(t, rule.Validate())
	require.Contains(t, rule.Validate().Error(), "invalid blob layer in nydus image manifest")

	rule.TargetParsed.NydusImage.Manifest.Layers = []ocispec.Descriptor{
		{
			MediaType: "application/vnd.oci.image.layer.nydus.blob.v1",
			Digest:    "sha256:09845cce1d983b158d4865fc37c23bbfb892d4775c786e8114d3cf868975c059",
			Size:      83528010,
			Annotations: map[string]string{
				"containerd.io/snapshot/nydus-blob": "true",
			},
		},
	}
	require.Error(t, rule.Validate())
	require.Contains(t, rule.Validate().Error(), "invalid bootstrap layer in nydus image manifest")

	rule.TargetParsed.NydusImage.Manifest.Layers = []ocispec.Descriptor{
		{
			MediaType: "application/vnd.oci.image.layer.nydus.blob.v1",
			Digest:    "sha256:09845cce1d983b158d4865fc37c23bbfb892d4775c786e8114d3cf868975c059",
			Size:      83528010,
			Annotations: map[string]string{
				"containerd.io/snapshot/nydus-blob": "true",
			},
		},
		{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    "sha256:aec98c9e3dce739877b8f5fe1cddd339de1db2b36c20995d76f6265056dbdb08",
			Size:      273320,
			Annotations: map[string]string{
				"containerd.io/snapshot/nydus-bootstrap":          "true",
				"containerd.io/snapshot/nydus-reference-blob-ids": "[\"09845cce1d983b158d4865fc37c23bbfb892d4775c786e8114d3cf868975c059\"]",
			},
		},
	}
	require.NoError(t, rule.Validate())
}
