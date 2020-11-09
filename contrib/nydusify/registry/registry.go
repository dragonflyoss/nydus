// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"

	"contrib/nydusify/signature"
	"contrib/nydusify/utils"
)

const (
	ManifestOSFeatureNydus   = "nydus.remoteimage.v1"
	MediaTypeNydusBlob       = "application/vnd.oci.image.layer.nydus.blob.v1"
	BootstrapFileNameInLayer = "image.boot"

	LayerAnnotationNydusBlob      = "containerd.io/snapshot/nydus-blob"
	LayerAnnotationNydusBootstrap = "containerd.io/snapshot/nydus-bootstrap"
	LayerAnnotationNydusSignature = "containerd.io/snapshot/nydus-signature"

	LayerPullWorkerCount = 5
	LayerPushWorkerCount = 5
)

type Image struct {
	WorkDir string
	Ref     name.Reference
	Img     *v1.Image
}

type RegistryOption struct {
	WorkDir string
	Source  string
	Target  string
}

type Registry struct {
	RegistryOption
	source Image
	target Image
}

func withDefaultAuth() authn.Keychain {
	return authn.DefaultKeychain
}

func New(option RegistryOption) (*Registry, error) {
	// Parse source & image reference from provided
	sourceRef, err := name.ParseReference(option.Source)
	if err != nil {
		return nil, errors.Wrap(err, "parse source reference")
	}

	targetRef, err := name.ParseReference(option.Target)
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
	targetImage = mutate.MediaType(targetImage, types.OCIManifestSchema1)

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

func (registry *Registry) Pull(callback func(*LayerJob) error) error {
	// Write source manifest to json file
	if err := registry.dumpManifest(&registry.source); err != nil {
		return err
	}

	// Start worker pool for pulling & decompressing
	layers, err := (*registry.source.Img).Layers()
	if err != nil {
		return errors.Wrap(err, "get source image layers")
	}

	layerJobs := []utils.Job{}
	for _, layer := range layers {
		layerJob, err := NewLayerJob(&registry.source, &registry.target)
		if err != nil {
			return err
		}
		layerJob.SetSourceLayer(layer)
		if err := layerJob.SetProgress(LayerSource, "BLOB"); err != nil {
			return errors.Wrap(err, "create blob layer progress")
		}
		layerJobs = append(layerJobs, layerJob)
	}
	layerJobRets := utils.NewQueueWorkerPool(layerJobs, LayerPullWorkerCount, MethodPull)

	// Pull layer and handle it by callback per layer
	for _, jobChan := range layerJobRets {
		jobRet := <-jobChan

		layerJob := jobRet.Job.(*LayerJob)
		hash, err := layerJob.SourceLayer.Digest()
		if err != nil {
			return err
		}
		if jobRet.Err != nil {
			return errors.Wrap(jobRet.Err, fmt.Sprintf("pull layer %s", hash.String()))
		}

		if err := callback(layerJob); err != nil {
			return err
		}
	}

	return nil
}

func (registry *Registry) PushBootstrapLayer(bootstrapPath string, privateKeyPath string) error {
	// Create tar gzip of bootstrap file
	compressedBootstrapPath := bootstrapPath + ".tar.gz"
	file, err := os.Create(compressedBootstrapPath)
	if err != nil {
		return errors.Wrap(err, "create bootstrap targz")
	}
	defer file.Close()

	if err := utils.CompressTargz(bootstrapPath, BootstrapFileNameInLayer, file); err != nil {
		return errors.Wrap(err, "compress bootstrap targz")
	}

	// Append signature of bootstap file
	layerAnnotations := map[string]string{
		LayerAnnotationNydusBootstrap: "true",
	}

	if strings.TrimSpace(privateKeyPath) != "" {
		signature, err := signature.SignFile(privateKeyPath, bootstrapPath)
		if err != nil {
			return errors.Wrap(err, "sign bootstrap file")
		}
		layerAnnotations[LayerAnnotationNydusSignature] = string(signature)
	}

	// Push nydus bootstrap layer
	layerJob, err := NewLayerJob(&registry.source, &registry.target)
	if err != nil {
		return err
	}
	layerJob.SetTargetLayer(compressedBootstrapPath, bootstrapPath, types.OCILayer, layerAnnotations)
	if err := layerJob.SetProgress(LayerTarget, "BOOT"); err != nil {
		return errors.Wrap(err, "create bootstrap layer progress")
	}
	if err := layerJob.Push(); err != nil {
		return errors.Wrap(err, "push bootstrap layer")
	}

	return nil
}

func (registry *Registry) PushManifest(multiPlatform bool) error {
	arch := runtime.GOARCH
	os := runtime.GOOS

	sourceManifest, err := (*registry.source.Img).Manifest()
	if err != nil {
		return errors.Wrap(err, "get source manifest")
	}
	if sourceManifest.Config.Platform != nil {
		arch = sourceManifest.Config.Platform.Architecture
		os = sourceManifest.Config.Platform.OS
	}

	hash := v1.Hash{}

	platform := v1.Platform{
		Architecture: arch,
		OS:           os,
		OSFeatures:   []string{ManifestOSFeatureNydus},
	}

	imageIndex := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: *registry.source.Img,
		Descriptor: v1.Descriptor{
			Platform: &v1.Platform{
				Architecture: arch,
				OS:           os,
			},
		},
	}, mutate.IndexAddendum{
		Add: *registry.target.Img,
		Descriptor: v1.Descriptor{
			Platform: &platform,
		},
	})

	if multiPlatform {
		hash, err = imageIndex.Digest()
		if err != nil {
			return err
		}
	} else {
		manifest, err := (*registry.target.Img).Manifest()
		if err != nil {
			return err
		}
		hash = manifest.Config.Digest
	}

	pushProgress, err := NewProgress(hash.String(), "MANI", StatusPushing, 100)
	if err != nil {
		return err
	}

	if multiPlatform {
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

	pushProgress.SetStatus(StatusPushed)
	pushProgress.SetFinish()

	// Write target manifest to json file
	if err := registry.dumpManifest(&registry.target); err != nil {
		return err
	}

	return nil
}
