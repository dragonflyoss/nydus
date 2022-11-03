// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

// manifestManager merges OCI and Nydus manifest, pushes them to
// remote registry
type manifestManager struct {
	sourceProvider provider.SourceProvider
	backend        backend.Backend
	remote         *remote.Remote
	multiPlatform  bool
	dockerV2Format bool
	buildInfo      *BuildInfo
}

// Try to get manifests from exists target image
func (mm *manifestManager) getExistsManifests(ctx context.Context) ([]ocispec.Descriptor, error) {
	desc, err := mm.remote.Resolve(ctx)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return []ocispec.Descriptor{}, nil
		}
		return nil, errors.Wrap(err, "Resolve image manifest index")
	}

	if desc.MediaType == images.MediaTypeDockerSchema2ManifestList ||
		desc.MediaType == ocispec.MediaTypeImageIndex {

		reader, err := mm.remote.Pull(ctx, *desc, true)
		if err != nil {
			return nil, errors.Wrap(err, "Pull image manifest index")
		}
		defer reader.Close()

		indexBytes, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, errors.Wrap(err, "Read image manifest index")
		}

		var index ocispec.Index
		if err := json.Unmarshal(indexBytes, &index); err != nil {
			return nil, errors.Wrap(err, "Unmarshal image manifest index")
		}

		return index.Manifests, nil
	}

	if desc.MediaType == images.MediaTypeDockerSchema2Manifest ||
		desc.MediaType == ocispec.MediaTypeImageManifest {
		return []ocispec.Descriptor{*desc}, nil
	}

	return []ocispec.Descriptor{}, nil
}

// Merge OCI and Nydus manifest into a manifest index, the OCI
// manifest of source image is not required to be provided
// `ociManifest`: The source image single manifest, which will be added to new manifest index.
func (mm *manifestManager) makeManifestIndex(
	ctx context.Context, existDescs []ocispec.Descriptor, nydusManifest, ociManifest *ocispec.Descriptor,
) (*ocispec.Index, error) {
	foundOCI := false
	descs := make([]ocispec.Descriptor, 0)
	// Traverse the entire manifest index to see if nydus image(same os/arch) already therein.
	// Possibly find image whose descriptor has no os/arch filled, then revise
	// the provided descriptor a little by giving it one os/arch pair `linux/amd64`.
	for _, desc := range existDescs {
		if desc.Platform != nil {
			// Input nydus image manifest must have platform filled before making this manifest index.
			if matched := utils.MatchNydusPlatform(&desc, nydusManifest.Platform.OS, nydusManifest.Platform.Architecture); matched {
				continue
			}

			if (desc.Platform.OS == nydusManifest.Platform.OS) &&
				(desc.Platform.Architecture == nydusManifest.Platform.Architecture) &&
				!utils.IsNydusPlatform(desc.Platform) {
				foundOCI = true
			}

			if desc.Platform.Architecture == "" {
				desc.Platform.Architecture = utils.SupportedArch
				logrus.Warnf("Image %s descriptor has no architecture", desc.Digest)
			}
			if desc.Platform.OS == "" {
				desc.Platform.OS = utils.SupportedOS
				logrus.Warnf("Image %s descriptor has no OS", desc.Digest)
			}
		} else {
			// TODO: Use image configuration's os/arch to fill descriptor.
			desc.Platform = &ocispec.Platform{
				OS:           utils.SupportedOS,
				Architecture: utils.SupportedArch,
			}
		}

		descs = append(descs, desc)
	}

	// Append the OCI manifest provided by source to manifest list
	if !foundOCI && ociManifest != nil {
		ociManifest.Platform = &ocispec.Platform{
			OS:           utils.SupportedOS,
			Architecture: utils.SupportedArch,
		}
		descs = append(descs, *ociManifest)
	}

	// Always put the nydus manifest to the last position of manifest list,
	// because client usually take the first image that matches os/arch.
	descs = append(descs, *nydusManifest)

	// Merge exists OCI manifests and Nydus manifest to manifest index
	index := ocispec.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		Manifests: descs,
	}

	return &index, nil
}

func (mm *manifestManager) CloneSourcePlatform(ctx context.Context, additionalOSFeatures string) (*ocispec.Platform, error) {
	sourceConfig, err := mm.sourceProvider.Config(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "can't take in source image configuration")
	}

	var features []string
	if additionalOSFeatures != "" {
		features = append(features, additionalOSFeatures)
	}

	// Source image configuration must exist according to OCI image spec.
	return &ocispec.Platform{
		OS:           sourceConfig.OS,
		Architecture: sourceConfig.Architecture,
		OSFeatures:   features,
	}, nil
}

func layersHex(layers []ocispec.Descriptor) []string {
	var digests []string
	for _, layer := range layers {
		digests = append(digests, layer.Digest.Hex())
	}
	return digests
}

func containsLayer(layers []ocispec.Descriptor, d digest.Digest) bool {
	for _, layer := range layers {
		if layer.Digest == d {
			return true
		}
	}
	return false
}

func appendBlobs(oldBlobs []string, newBlobs []string) []string {
	for _, newBlob := range newBlobs {
		exist := false
		for _, oldBlob := range oldBlobs {
			if oldBlob == newBlob {
				exist = true
				break
			}
		}
		if !exist {
			oldBlobs = append(oldBlobs, newBlob)
		}
	}
	return oldBlobs
}

func (mm *manifestManager) Push(ctx context.Context, builtLayers []*buildLayer) error {
	var (
		referenceBlobs []string
		layers         []ocispec.Descriptor
	)
	for idx, _layer := range builtLayers {
		record := _layer.GetCacheRecord()
		referenceBlobs = appendBlobs(referenceBlobs, layersHex(_layer.referenceBlobs))
		if record.NydusBlobDesc != nil {
			// For registry backend, we need to write the blob layer to
			// manifest to prevent them from being deleted by registry GC.
			if mm.backend.Type() == backend.RegistryBackend {
				layers = append(layers, *record.NydusBlobDesc)
			}
		}
		// try add reference blob layers to manifest
		if mm.backend.Type() == backend.RegistryBackend {
			for _, blobDesc := range _layer.referenceBlobs {
				if !containsLayer(layers, blobDesc.Digest) {
					layers = append(layers, blobDesc)
				}
			}
		}

		// Only need to write latest bootstrap layer in nydus manifest
		if idx == len(builtLayers)-1 {
			if len(referenceBlobs) > 0 {
				blobListBytes, err := json.Marshal(referenceBlobs)
				if err != nil {
					return errors.Wrap(err, "Marshal blob list")
				}
				record.NydusBootstrapDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs] = string(blobListBytes)
			}
			layers = append(layers, *record.NydusBootstrapDesc)
		}
	}

	ociConfig, err := mm.sourceProvider.Config(ctx)
	if err != nil {
		return errors.Wrap(err, "Get source image config")
	}
	ociConfig.RootFS.DiffIDs = []digest.Digest{}
	ociConfig.History = []ocispec.History{}

	// Remove useless annotations from layer
	validAnnotationKeys := map[string]bool{
		utils.LayerAnnotationNydusBlob:             true,
		utils.LayerAnnotationNydusReferenceBlobIDs: true,
		utils.LayerAnnotationNydusBootstrap:        true,
		utils.LayerAnnotationNydusFsVersion:        true,
	}
	for idx, desc := range layers {
		layerDiffID := digest.Digest(desc.Annotations[utils.LayerAnnotationUncompressed])
		if layerDiffID == "" {
			layerDiffID = desc.Digest
		}
		ociConfig.RootFS.DiffIDs = append(ociConfig.RootFS.DiffIDs, layerDiffID)
		if desc.Annotations != nil {
			newAnnotations := make(map[string]string)
			for key, value := range desc.Annotations {
				if validAnnotationKeys[key] {
					newAnnotations[key] = value
				}
			}
			layers[idx].Annotations = newAnnotations
		}
	}

	// Push Nydus image config
	configMediaType := ocispec.MediaTypeImageConfig
	if mm.dockerV2Format {
		configMediaType = images.MediaTypeDockerSchema2Config
	}
	configDesc, configBytes, err := utils.MarshalToDesc(ociConfig, configMediaType)
	if err != nil {
		return errors.Wrap(err, "Marshal source image config")
	}

	if err := mm.remote.Push(ctx, *configDesc, true, bytes.NewReader(configBytes)); err != nil {
		return errors.Wrap(err, "Push Nydus image config")
	}

	manifestMediaType := ocispec.MediaTypeImageManifest
	if mm.dockerV2Format {
		manifestMediaType = images.MediaTypeDockerSchema2Manifest
	}

	// Push Nydus image manifest
	nydusManifest := struct {
		MediaType string `json:"mediaType,omitempty"`
		ocispec.Manifest
	}{
		MediaType: manifestMediaType,
		Manifest: ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config:      *configDesc,
			Layers:      layers,
			Annotations: mm.buildInfo.Dump(),
		},
	}

	nydusManifestDesc, manifestBytes, err := utils.MarshalToDesc(nydusManifest, manifestMediaType)
	if err != nil {
		return errors.Wrap(err, "Marshal Nydus image manifest")
	}

	p, err := mm.CloneSourcePlatform(ctx, utils.ManifestOSFeatureNydus)
	if err != nil {
		return errors.Wrap(err, "clone source platform")
	}

	nydusManifestDesc.Platform = p

	if !mm.multiPlatform {
		if err := mm.remote.Push(ctx, *nydusManifestDesc, false, bytes.NewReader(manifestBytes)); err != nil {
			return errors.Wrap(err, "Push nydus image manifest")
		}
		return nil
	}

	if err := mm.remote.Push(ctx, *nydusManifestDesc, true, bytes.NewReader(manifestBytes)); err != nil {
		return errors.Wrap(err, "Push nydus image manifest")
	}

	// Push manifest index, includes OCI manifest and Nydus manifest
	ociManifestDesc, err := mm.sourceProvider.Manifest(ctx)
	if err != nil {
		return errors.Wrap(err, "Get source image manifest")
	}

	if ociManifestDesc != nil {
		p, err := mm.CloneSourcePlatform(ctx, "")
		if err != nil {
			return errors.Wrap(err, "clone source platform")
		}
		ociManifestDesc.Platform = p
	}

	existManifests, err := mm.getExistsManifests(ctx)
	if err != nil {
		return errors.Wrap(err, "Get remote existing manifest index")
	}

	ociIndex, err := mm.makeManifestIndex(ctx, existManifests, nydusManifestDesc, ociManifestDesc)
	if err != nil {
		return errors.Wrap(err, "Make manifest index for target")
	}

	indexMediaType := ocispec.MediaTypeImageIndex
	if mm.dockerV2Format {
		indexMediaType = images.MediaTypeDockerSchema2ManifestList
	}

	index := struct {
		MediaType string `json:"mediaType,omitempty"`
		ocispec.Index
	}{
		MediaType: indexMediaType,
		Index:     *ociIndex,
	}

	indexDesc, indexBytes, err := utils.MarshalToDesc(index, indexMediaType)
	if err != nil {
		return errors.Wrap(err, "Marshal image manifest index")
	}

	if err := mm.remote.Push(ctx, *indexDesc, false, bytes.NewReader(indexBytes)); err != nil {
		return errors.Wrap(err, "Push image manifest index")
	}

	return nil
}
