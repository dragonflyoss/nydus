// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"context"
	"contrib/nydusify/remote"
	"contrib/nydusify/utils"
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Opt provides parser options.
type Opt struct {
	Ref      string
	Insecure bool
}

// Parser parses Nydus image manifest, manifest index and
// image config into Parsed object.
type Parser struct {
	Opt
	remote *remote.Remote
}

// Parsed presents OCI and Nydus image manifest.
type Parsed struct {
	Index          *ocispec.Index
	OCIManifest    *ocispec.Manifest
	NydusManifest  *ocispec.Manifest
	OCIConfig      *ocispec.Image
	NydusConfig    *ocispec.Image
	NydusBootstrap io.ReadCloser
}

// New creates Nydus image parser instance.
func New(opt Opt) (*Parser, error) {
	remote, err := remote.NewRemote(remote.RemoteOpt{
		Ref:      opt.Ref,
		Insecure: opt.Insecure,
	})
	if err != nil {
		return nil, errors.Wrap(err, "init remote")
	}

	parser := &Parser{
		Opt:    opt,
		remote: remote,
	}

	return parser, nil
}

func (parser *Parser) pull(desc *ocispec.Descriptor, res interface{}) error {
	reader, err := parser.remote.Pull(context.Background(), *desc, true)
	if err != nil {
		return errors.Wrap(err, "pull image resource")
	}
	defer reader.Close()

	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return errors.Wrap(err, "read image resource")
	}

	if err := json.Unmarshal(bytes, res); err != nil {
		return errors.Wrap(err, "unmarshal image resource")
	}

	return nil
}

func (parser *Parser) pullManifest(desc *ocispec.Descriptor) (*ocispec.Manifest, error) {
	var manifest ocispec.Manifest
	if err := parser.pull(desc, &manifest); err != nil {
		return nil, errors.Wrap(err, "pull image manifest")
	}
	return &manifest, nil
}

func (parser *Parser) pullConfig(desc *ocispec.Descriptor) (*ocispec.Image, error) {
	var config ocispec.Image
	if err := parser.pull(desc, &config); err != nil {
		return nil, errors.Wrap(err, "pull image config")
	}
	return &config, nil
}

func (parser *Parser) pullIndex(desc *ocispec.Descriptor) (*ocispec.Index, error) {
	var index ocispec.Index
	if err := parser.pull(desc, &index); err != nil {
		return nil, errors.Wrap(err, "pull image index")
	}
	return &index, nil
}

func findBootstrapDesc(manifest *ocispec.Manifest) *ocispec.Descriptor {
	layers := manifest.Layers
	if len(layers) != 0 {
		bootstrapDesc := layers[len(layers)-1]
		if (bootstrapDesc.MediaType == ocispec.MediaTypeImageLayerGzip ||
			bootstrapDesc.MediaType == images.MediaTypeDockerSchema2LayerGzip) &&
			bootstrapDesc.Annotations[utils.LayerAnnotationNydusBootstrap] == "true" {
			return &bootstrapDesc
		}
	}
	return nil
}

// Parse parses Nydus image reference into Parsed object.
func (parser *Parser) Parse() (*Parsed, error) {
	logrus.Infof("Parsing image %s", parser.Ref)

	parsed := Parsed{}

	imageDesc, err := parser.remote.Resolve(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "resolve image")
	}

	var ociDesc *ocispec.Descriptor
	var nydusDesc *ocispec.Descriptor

	switch imageDesc.MediaType {
	// Handle image manifest
	case ocispec.MediaTypeImageManifest, images.MediaTypeDockerSchema2Manifest:
		manifest, err := parser.pullManifest(imageDesc)
		if err != nil {
			return nil, err
		}
		bootstrapDesc := findBootstrapDesc(manifest)
		if bootstrapDesc != nil {
			nydusDesc = imageDesc
			parsed.NydusManifest = manifest
		} else {
			ociDesc = imageDesc
		}

	// Handle image manifest index
	case ocispec.MediaTypeImageIndex, images.MediaTypeDockerSchema2ManifestList:
		index, err := parser.pullIndex(imageDesc)
		if err != nil {
			return nil, err
		}
		parsed.Index = index

		for idx := range index.Manifests {
			desc := index.Manifests[idx]
			if desc.Platform != nil {
				if desc.Platform.OS == "linux" && desc.Platform.Architecture == "amd64" ||
					desc.Platform.OS == "" && desc.Platform.Architecture == "" {
					if desc.Platform.OSFeatures != nil &&
						len(desc.Platform.OSFeatures) == 1 &&
						desc.Platform.OSFeatures[0] == utils.ManifestOSFeatureNydus {
						nydusDesc = &desc
					} else {
						ociDesc = &desc
					}
				}
			} else {
				ociDesc = &desc
			}
		}
	}

	if ociDesc != nil {
		parsed.OCIManifest, err = parser.pullManifest(ociDesc)
		if err != nil {
			return nil, errors.Wrap(err, "pull OCI image manifest")
		}
		parsed.OCIConfig, err = parser.pullConfig(&parsed.OCIManifest.Config)
		if err != nil {
			return nil, errors.Wrap(err, "pull OCI image config")
		}
	}

	if nydusDesc != nil {
		if parsed.NydusManifest == nil {
			parsed.NydusManifest, err = parser.pullManifest(nydusDesc)
			if err != nil {
				return nil, errors.Wrap(err, "pull Nydus image manifest")
			}
		}
		parsed.NydusConfig, err = parser.pullConfig(&parsed.NydusManifest.Config)
		if err != nil {
			return nil, errors.Wrap(err, "pull Nydus image config")
		}
		// Parse bootstrap layer in Nydus image manifest
		bootstrapDesc := findBootstrapDesc(parsed.NydusManifest)
		if bootstrapDesc != nil {
			parsed.NydusBootstrap, err = parser.remote.Pull(context.Background(), *bootstrapDesc, true)
			if err != nil {
				return nil, errors.Wrap(err, "pull Nydus bootstrap layer")
			}
		}
	}

	return &parsed, nil
}
