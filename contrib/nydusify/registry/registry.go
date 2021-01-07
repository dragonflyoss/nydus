// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	blobbackend "contrib/nydusify/backend"
	"contrib/nydusify/cache"
	buildcache "contrib/nydusify/cache"
	"contrib/nydusify/utils"
)

const (
	LayerPullWorkerCount = 5
	LayerPushWorkerCount = 5
)

type Image struct {
	WorkDir string
	Ref     name.Reference
	Img     *v1.Image
}

type RegistryOption struct {
	WorkDir            string
	Source             string
	Target             string
	SourceInsecure     bool
	TargetInsecure     bool
	Backend            blobbackend.Backend
	BuildCache         string
	BuildCacheInsecure bool
	SignatureKeyPath   string
	MultiPlatform      bool
	DockerV2Format     bool
}

type Registry struct {
	RegistryOption
	source    Image
	target    Image
	cache     *cache.Cache
	layerJobs []*LayerJob
}

func withDefaultAuth() authn.Keychain {
	return authn.DefaultKeychain
}

func getLayerChainID(layers []v1.Layer) (*digest.Digest, error) {
	digests := []digest.Digest{}
	for _, layer := range layers {
		layerDigest, err := layer.DiffID()
		if err != nil {
			return nil, errors.Wrap(err, "get layer ChainID")
		}
		digests = append(digests, digest.Digest(layerDigest.String()))
	}
	chainID := identity.ChainID(digests)
	return &chainID, nil
}

func New(option RegistryOption) (*Registry, error) {
	// Parse source & image reference from provided
	sourceOpts := []name.Option{}
	if option.SourceInsecure {
		sourceOpts = append(sourceOpts, name.Insecure)
	}
	sourceRef, err := name.ParseReference(option.Source, sourceOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "parse source reference")
	}
	targetOpts := []name.Option{}
	if option.TargetInsecure {
		targetOpts = append(targetOpts, name.Insecure)
	}
	targetRef, err := name.ParseReference(option.Target, targetOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "parse target reference")
	}

	// Fetch source image manifest
	sourceImage, err := remote.Image(
		sourceRef,
		remote.WithAuthFromKeychain(withDefaultAuth()),
		remote.WithPlatform(v1.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		}),
	)
	if err != nil {
		return nil, errors.Wrap(err, "fetch source image")
	}

	// Make new target image based on source config
	sourceConfig, err := sourceImage.ConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "prepare target config")
	}
	sourceConfig.RootFS.DiffIDs = []v1.Hash{}
	sourceConfig.History = []v1.History{}

	targetImage, err := mutate.ConfigFile(empty.Image, sourceConfig)
	if err != nil {
		return nil, errors.Wrap(err, "prepare target image")
	}

	if option.DockerV2Format {
		targetImage = mutate.MediaType(targetImage, types.DockerManifestSchema2)
	} else {
		targetImage = mutate.MediaType(targetImage, types.OCIManifestSchema1)
	}

	// Init Nydus build cache
	var cache *buildcache.Cache
	if option.BuildCache != "" {
		cache, err = buildcache.New(buildcache.Opt{
			Ref:            option.BuildCache,
			Insecure:       option.BuildCacheInsecure,
			DockerV2Format: option.DockerV2Format,
		})
		if err != nil {
			return nil, errors.Wrap(err, "init build cache")
		}
	}

	return &Registry{
		RegistryOption: option,
		source: Image{
			WorkDir: filepath.Join(option.WorkDir, sourceRef.String()),
			Ref:     sourceRef,
			Img:     &sourceImage,
		},
		target: Image{
			WorkDir: filepath.Join(option.WorkDir, targetRef.String()),
			Ref:     targetRef,
			Img:     &targetImage,
		},
		cache: cache,
	}, nil
}

func (registry *Registry) dumpManifest(image *Image) error {
	rawManifest, err := (*image.Img).RawManifest()
	if err != nil {
		return errors.Wrap(err, "get image manifest")
	}
	manifestFile := filepath.Join(image.WorkDir, "manifest.json")
	if err := ioutil.WriteFile(manifestFile, rawManifest, 0644); err != nil {
		return errors.Wrap(err, "write image manifest")
	}

	return nil
}

func (registry *Registry) dumpConfig(image *Image) error {
	rawConfig, err := (*image.Img).RawConfigFile()
	if err != nil {
		return errors.Wrap(err, "get image config")
	}
	manifestFile := filepath.Join(image.WorkDir, "config.json")
	if err := ioutil.WriteFile(manifestFile, rawConfig, 0644); err != nil {
		return errors.Wrap(err, "write image config")
	}

	return nil
}

func (registry *Registry) makeLayerJobByCache(sourceLayerChainID digest.Digest) (*LayerJob, error) {
	if registry.cache == nil {
		return nil, nil
	}

	record, err := registry.cache.Check(sourceLayerChainID)
	if err != nil {
		return nil, errors.Wrap(err, "check cache record")
	}
	if record == nil {
		return nil, nil
	}

	var cachedBlobLayer *Layer
	if record.NydusBlobDesc != nil {
		cachedBlobLayer, err = DescToLayer(*record.NydusBlobDesc, record.NydusBlobDesc.Digest)
		if err != nil {
			return nil, errors.Wrap(err, "blob desc to layer")
		}
	}

	cachedBootstrapLayer, err := DescToLayer(*record.NydusBootstrapDesc, record.NydusBootstrapDiffID)
	if err != nil {
		return nil, errors.Wrap(err, "bootstrap desc to layer")
	}

	return &LayerJob{
		Source:               &registry.source,
		Target:               &registry.target,
		Backend:              registry.Backend,
		SourceLayerChainID:   sourceLayerChainID,
		TargetBlobLayer:      cachedBlobLayer,
		TargetBootstrapLayer: cachedBootstrapLayer,
		Cached:               true,
	}, nil
}

func (registry *Registry) makeTargetImageLayers() error {
	blobIDs := []string{}
	for idx, job := range registry.layerJobs {
		if job.TargetBlobLayer != nil {
			blobDigest, err := job.TargetBlobLayer.Digest()
			if err != nil {
				return err
			}
			blobIDs = append(blobIDs, blobDigest.Hex)
			if registry.Backend == nil {
				targetImage, err := mutate.Append(*registry.target.Img, mutate.Addendum{
					Layer: job.TargetBlobLayer,
					History: v1.History{
						CreatedBy: fmt.Sprintf("nydusify"),
					},
					Annotations: map[string]string{
						utils.LayerAnnotationNydusBlob: "true",
					},
				})
				if err != nil {
					return errors.Wrap(err, "append target blob layer")
				}
				*registry.target.Img = targetImage
			}
		}

		if idx == len(registry.layerJobs)-1 {
			mediaType := types.OCILayer
			if registry.DockerV2Format {
				mediaType = types.DockerLayer
			}
			// Write blob digest list to annotation, so that we can track
			// these blob files were uploaded to foreign storage backend
			blobIDsBytes, err := json.Marshal(blobIDs)
			if err != nil {
				return err
			}
			annotations := map[string]string{
				utils.LayerAnnotationNydusBootstrap: "true",
				utils.LayerAnnotationNydusBlobIDs:   string(blobIDsBytes),
			}
			targetImage, err := mutate.Append(*registry.target.Img, mutate.Addendum{
				MediaType: mediaType,
				Layer:     job.TargetBootstrapLayer,
				History: v1.History{
					CreatedBy: fmt.Sprintf("nydusify"),
				},
				Annotations: annotations,
			})
			if err != nil {
				return errors.Wrap(err, "append target bootstrap layer")
			}
			*registry.target.Img = targetImage
		}
	}

	return nil
}

func (registry *Registry) Pull(build func(
	*LayerJob,
	func(string) (string, error),
) error) error {
	// Write source manifest to json file
	if err := registry.dumpManifest(&registry.source); err != nil {
		return errors.Wrap(err, "dump source manifest")
	}

	// Start worker pool for pulling & decompressing
	layers, err := (*registry.source.Img).Layers()
	if err != nil {
		return errors.Wrap(err, "get source image layers")
	}

	layerJobs := []utils.Job{}
	var parentLayerJob *LayerJob
	for idx, layer := range layers {
		// Create layer job to push nydus bootstrap and blob layer
		var sourceLayerChainID *digest.Digest
		if idx == len(layers)-1 {
			sourceLayerChainID, err = getLayerChainID(layers)
		} else {
			sourceLayerChainID, err = getLayerChainID(layers[:idx+1])
		}
		if err != nil {
			return err
		}

		layerJob, err := registry.makeLayerJobByCache(*sourceLayerChainID)
		if err != nil {
			return err
		}

		if layerJob == nil {
			layerJob = &LayerJob{
				Source:             &registry.source,
				Target:             &registry.target,
				Backend:            registry.Backend,
				SourceLayerChainID: *sourceLayerChainID,
				Cached:             false,
			}
			layerJob.SetSourceLayer(layer)
			layerJobs = append(layerJobs, layerJob)
		} else {
			logrus.WithField("ChainID", sourceLayerChainID).Infof("[SOUR] Skip")
		}

		layerJob.Parent = parentLayerJob
		parentLayerJob = layerJob
		registry.layerJobs = append(registry.layerJobs, layerJob)
	}
	layerJobRets := utils.NewQueueWorkerPool(layerJobs, LayerPullWorkerCount, MethodPull)

	// Pull source layer and build it one by one
	for _, jobChan := range layerJobRets {
		jobRet := <-jobChan

		layerJob := jobRet.Job.(*LayerJob)
		layerDigest, err := layerJob.SourceLayer.Digest()
		if err != nil {
			return err
		}

		if jobRet.Err != nil {
			return errors.Wrap(jobRet.Err, fmt.Sprintf("pull layer %s", layerDigest))
		}

		// The func pulls bootstrap layer and write the bootstrap file
		// to targetDir, the build flow uses it as parent bootstrap
		pullBootstrapFunc := func(targetDir string) (string, error) {
			bootstrapDesc, err := layerJob.Parent.TargetBootstrapLayer.Desc()
			if err != nil {
				return "", err
			}
			targetPath := filepath.Join(targetDir, layerJob.Parent.SourceLayerChainID.String())
			logrus.WithField("Digest", bootstrapDesc.Digest).Infof("[BOOT] Pulling")
			if err := registry.cache.PullBootstrap(bootstrapDesc, targetPath); err != nil {
				return "", errors.Wrap(err, "pull bootstrap")
			}
			logrus.WithField("Digest", bootstrapDesc.Digest).Infof("[BOOT] Pulled")
			return targetPath, nil
		}

		logrus.WithField("Digest", layerDigest).Infof("[SOUR] Building")
		if err := build(layerJob, pullBootstrapFunc); err != nil {
			return errors.Wrap(err, "build layer")
		}
		logrus.WithField("Digest", layerDigest).Infof("[SOUR] Built")
	}

	return nil
}

func (registry *Registry) PushManifest() error {
	arch := runtime.GOARCH
	os := runtime.GOOS

	sourceConfig, err := (*registry.source.Img).ConfigFile()
	if err != nil {
		return errors.Wrap(err, "get source manifest")
	}
	if sourceConfig != nil {
		arch = sourceConfig.Architecture
		os = sourceConfig.OS
	}

	sourceMediaType, err := (*registry.source.Img).MediaType()
	if err != nil {
		return errors.Wrap(err, "get source media type")
	}

	targetMediaType, err := (*registry.target.Img).MediaType()
	if err != nil {
		return errors.Wrap(err, "get target media type")
	}

	platform := v1.Platform{
		Architecture: arch,
		OS:           os,
		OSFeatures:   []string{utils.ManifestOSFeatureNydus},
	}

	if err := registry.makeTargetImageLayers(); err != nil {
		return err
	}

	// Write target manifest to json file
	if err := registry.dumpManifest(&registry.target); err != nil {
		return errors.Wrap(err, "dump target manifest")
	}

	// Write target config to json file
	if err := registry.dumpConfig(&registry.target); err != nil {
		return errors.Wrap(err, "dump target config")
	}

	imageIndex := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: *registry.source.Img,
		Descriptor: v1.Descriptor{
			MediaType: sourceMediaType,
			Platform: &v1.Platform{
				Architecture: arch,
				OS:           os,
			},
		},
	}, mutate.IndexAddendum{
		Add: *registry.target.Img,
		Descriptor: v1.Descriptor{
			MediaType: targetMediaType,
			Platform:  &platform,
		},
	})

	if registry.DockerV2Format {
		imageIndex = mutate.IndexMediaType(imageIndex, types.DockerManifestList)
	} else {
		imageIndex = mutate.IndexMediaType(imageIndex, types.OCIImageIndex)
	}

	if registry.MultiPlatform {
		if err := remote.WriteIndex(
			registry.target.Ref,
			imageIndex,
			remote.WithAuthFromKeychain(withDefaultAuth()),
		); err != nil {
			return errors.Wrap(err, "push target image index")
		}
	} else {
		if err := remote.Write(
			registry.target.Ref,
			*registry.target.Img,
			remote.WithAuthFromKeychain(withDefaultAuth()),
			remote.WithPlatform(platform),
		); err != nil {
			return errors.Wrap(err, "push target image")
		}
	}

	return nil
}

func (registry *Registry) PullCache() error {
	if registry.cache == nil {
		return nil
	}
	logrus.Infof("Pulling cache image %s", registry.BuildCache)
	return registry.cache.Import()
}

func (registry *Registry) PushCache() error {
	if registry.cache == nil {
		return nil
	}

	logrus.Infof("Pushing cache image %s", registry.BuildCache)

	cacheRecords := []cache.CacheRecordWithChainID{}

	for idx := range registry.layerJobs {
		layerJob := registry.layerJobs[idx]

		blobLayer := layerJob.TargetBlobLayer
		bootstrapLayer := layerJob.TargetBootstrapLayer

		var blobDesc *ocispec.Descriptor
		if blobLayer != nil {
			_blobDesc, err := blobLayer.Desc()
			if err != nil {
				return errors.Wrap(err, "get blob digest")
			}
			blobDesc = _blobDesc
		}

		bootstrapDesc, err := bootstrapLayer.Desc()
		if err != nil {
			return errors.Wrap(err, "get bootstrap digest")
		}

		if !layerJob.Cached {
			// Push bootstrap layer to cache image, should be fast
			// because the layer has been pushed to registry in the
			// previous nydus build workflow
			reader, err := bootstrapLayer.Compressed()
			if err != nil {
				return errors.Wrap(err, "get compressed")
			}
			defer reader.Close()
			if err := registry.cache.PushBootstrap(reader, bootstrapDesc); err != nil {
				return errors.Wrap(err, "push bootstrap")
			}
		}

		bootstrapDiffID, err := bootstrapLayer.DiffID()
		if err != nil {
			return errors.Wrap(err, "get bootstrap diff id")
		}

		cacheRecord := cache.CacheRecordWithChainID{
			SourceChainID: layerJob.SourceLayerChainID,
			CacheRecord: cache.CacheRecord{
				NydusBlobDesc:        blobDesc,
				NydusBootstrapDesc:   bootstrapDesc,
				NydusBootstrapDiffID: digest.Digest(bootstrapDiffID.String()),
			},
		}

		cacheRecords = append(cacheRecords, cacheRecord)
	}

	// Import cache from registry again, to use latest
	// cache record list, ignore the error
	if err := registry.cache.Import(); err != nil {
		logrus.Warnf("Re-pull cache image %s: %s", registry.BuildCache, err)
	}

	registry.cache.Push(cacheRecords)

	if err := registry.cache.Export(); err != nil {
		return errors.Wrap(err, "export cache")
	}

	return nil
}
