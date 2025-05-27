// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/containerd/v2/core/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

// Parser parses OCI & Nydus image manifest, manifest index and
// image config into Parsed object, see the Nydus image example:
// examples/manifest/index.json, examples/manifest/manifest.json.
type Parser struct {
	Remote *remote.Remote
	// Principle to select platform arch/os is that nydus only works on top of linux
	// and interestedArch has to be specified in case of manifest list. So nydusify
	// knows how to choose the source image. In case of single manifest, `interestedArch`
	// is the same with origin.
	interestedArch string
}

// Image presents image contents.
type Image struct {
	Desc     ocispec.Descriptor
	Manifest ocispec.Manifest
	Config   ocispec.Image
}

// Parsed presents OCI and Nydus image manifest.
// Nydus image conversion only works on top of an existed oci image whose platform is linux/amd64
type Parsed struct {
	Remote *remote.Remote
	Index  *ocispec.Index
	// The base image from which to generate nydus image.
	OCIImage   *Image
	NydusImage *Image
}

// New creates Nydus image parser instance.
func New(remote *remote.Remote, interestedArch string) (*Parser, error) {
	if !utils.IsSupportedArch(interestedArch) {
		return nil, fmt.Errorf("invalid arch %s", interestedArch)
	}
	return &Parser{
		Remote:         remote,
		interestedArch: interestedArch,
	}, nil
}

// Try to find the topmost layer in Nydus manifest, it should
// be a Nydus bootstrap layer, see examples/manifest/manifest.json
func FindNydusBootstrapDesc(manifest *ocispec.Manifest) *ocispec.Descriptor {
	layers := manifest.Layers
	if len(layers) != 0 {
		desc := &layers[len(layers)-1]
		if (desc.MediaType == ocispec.MediaTypeImageLayerGzip ||
			desc.MediaType == images.MediaTypeDockerSchema2LayerGzip) &&
			desc.Annotations[utils.LayerAnnotationNydusBootstrap] == "true" {
			return desc
		}
	}
	return nil
}

func (parser *Parser) pull(ctx context.Context, desc *ocispec.Descriptor, res interface{}) error {
	reader, err := parser.Remote.Pull(ctx, *desc, true)
	if err != nil {
		return errors.Wrap(err, "pull image resource")
	}
	defer reader.Close()

	bytes, err := io.ReadAll(reader)
	if err != nil {
		return errors.Wrap(err, "read image resource")
	}

	if err := json.Unmarshal(bytes, res); err != nil {
		return errors.Wrap(err, "unmarshal image resource")
	}

	return nil
}

func (parser *Parser) pullManifest(ctx context.Context, desc *ocispec.Descriptor) (*ocispec.Manifest, error) {
	var manifest ocispec.Manifest
	if err := parser.pull(ctx, desc, &manifest); err != nil {
		return nil, errors.Wrap(err, "pull image manifest")
	}
	return &manifest, nil
}

func (parser *Parser) pullConfig(ctx context.Context, desc *ocispec.Descriptor) (*ocispec.Image, error) {
	var config ocispec.Image
	if err := parser.pull(ctx, desc, &config); err != nil {
		return nil, errors.Wrap(err, "pull image config")
	}
	return &config, nil
}

func (parser *Parser) pullIndex(ctx context.Context, desc *ocispec.Descriptor) (*ocispec.Index, error) {
	var index ocispec.Index
	if err := parser.pull(ctx, desc, &index); err != nil {
		return nil, errors.Wrap(err, "pull image index")
	}
	return &index, nil
}

func (parser *Parser) parseImage(
	ctx context.Context, desc *ocispec.Descriptor, onlyManifest *ocispec.Manifest, ignoreArch bool,
) (*Image, error) {
	var manifest *ocispec.Manifest
	var err error
	if onlyManifest != nil {
		manifest = onlyManifest
	} else {
		manifest, err = parser.pullManifest(ctx, desc)
		if err != nil {
			return nil, errors.Wrap(err, "pull image manifest")
		}
	}
	config, err := parser.pullConfig(ctx, &manifest.Config)
	if err != nil {
		return nil, errors.Wrap(err, "pull image config")
	}

	if config.OS == "" || config.Architecture == "" {
		err = errors.New("Source image configuration does not have os or architecture")
		if ignoreArch {
			logrus.WithError(err).Warn("Ignore image arch")
		} else {
			return nil, err
		}
	}

	// Just give user a simple hint telling option was ignored.
	if config.Architecture != parser.interestedArch {
		err = errors.Errorf("Found arch %s, but the specified target arch (--platform) is %s", config.Architecture, parser.interestedArch)
		if ignoreArch {
			logrus.WithError(err).Warn("Ignore image arch, attempting to continue converting")
		} else {
			return nil, err
		}
	}

	return &Image{
		Desc:     *desc,
		Manifest: *manifest,
		Config:   *config,
	}, nil
}

// PullNydusBootstrap pulls Nydus bootstrap layer from Nydus image.
func (parser *Parser) PullNydusBootstrap(ctx context.Context, image *Image) (io.ReadCloser, error) {
	bootstrapDesc := FindNydusBootstrapDesc(&image.Manifest)
	if bootstrapDesc == nil {
		return nil, fmt.Errorf("not found Nydus bootstrap layer in manifest")
	}
	reader, err := parser.Remote.Pull(ctx, *bootstrapDesc, true)
	if err != nil {
		return nil, errors.Wrap(err, "pull Nydus bootstrap layer")
	}
	return reader, nil
}

func (parser *Parser) matchImagePlatform(desc *ocispec.Descriptor) bool {
	if parser.interestedArch == desc.Platform.Architecture && desc.Platform.OS == "linux" {
		return true
	}
	return false
}

// Parse parses Nydus image reference into Parsed object.
func (parser *Parser) Parse(ctx context.Context) (*Parsed, error) {
	parsed := Parsed{
		Remote: parser.Remote,
	}

	imageDesc, err := parser.Remote.Resolve(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
			logrus.Warningln("try to enable \"--source-insecure\" / \"--target-insecure\" option")
		}
		return nil, errors.Wrap(err, "resolve image")
	}

	var ociDesc *ocispec.Descriptor
	var nydusDesc *ocispec.Descriptor
	var onlyManifest *ocispec.Manifest
	var ignoreArch bool

	switch imageDesc.MediaType {
	// Handle image manifest
	case ocispec.MediaTypeImageManifest, images.MediaTypeDockerSchema2Manifest:
		// Because there is only one manifest, the source is determined,
		// `interestedArch` does not have effect.
		onlyManifest, err = parser.pullManifest(ctx, imageDesc)
		if err != nil {
			return nil, err
		}

		bootstrapDesc := FindNydusBootstrapDesc(onlyManifest)
		if bootstrapDesc != nil {
			nydusDesc = imageDesc
		} else {
			ociDesc = imageDesc
		}
		// For a single manifest image, we just ignore the arch, so that allowing
		// to do a default conversion on a different arch's host, for example
		// converting an arm64 image on an amd64 host.
		ignoreArch = true

	// Handle image manifest index
	case ocispec.MediaTypeImageIndex, images.MediaTypeDockerSchema2ManifestList:
		index, err := parser.pullIndex(ctx, imageDesc)
		if err != nil {
			return nil, err
		}
		parsed.Index = index

		for idx := range index.Manifests {
			desc := index.Manifests[idx]
			if desc.Platform != nil {
				// Currently, parser only finds one interested image.
				if parser.matchImagePlatform(&desc) {
					if utils.IsNydusPlatform(desc.Platform) {
						nydusDesc = &desc
					} else {
						ociDesc = &desc
					}
				}
			} else {
				// FIXME: Returning the first image without platform specified is subtle.
				// It might not violate Image spec.
				ociDesc = &desc
				logrus.Warnf("Will cook a image without platform, %s", ociDesc.Digest)
			}
		}
	}

	if ociDesc != nil {
		parsed.OCIImage, err = parser.parseImage(ctx, ociDesc, onlyManifest, ignoreArch)
		if err != nil {
			return nil, errors.Wrap(err, "Parse OCI image")
		}
	}

	if nydusDesc != nil {
		parsed.NydusImage, err = parser.parseImage(ctx, nydusDesc, onlyManifest, ignoreArch)
		if err != nil {
			return nil, errors.Wrap(err, "Parse Nydus image")
		}
	}

	return &parsed, nil
}
