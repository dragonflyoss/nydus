// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	blobbackend "contrib/nydusify/backend"
	"contrib/nydusify/cache"
	"contrib/nydusify/nydus"
	"contrib/nydusify/registry"
)

type Option struct {
	Source         string
	Target         string
	SourceInsecure bool
	TargetInsecure bool

	WorkDir          string
	PrefetchDir      string
	SignatureKeyPath string
	NydusImagePath   string
	MultiPlatform    bool
	DockerV2Format   bool

	BackendType   string
	BackendConfig string

	BuildCache           string
	BuildCacheInsecure   bool
	BuildCacheMaxRecords uint
}

type Converter struct {
	Option
	sourceDir string
	targetDir string
}

func New(option Option) (*Converter, error) {
	// Make directory for source image
	sourceDir := filepath.Join(option.WorkDir, option.Source)
	if err := os.RemoveAll(sourceDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sourceDir, 0770); err != nil {
		return nil, errors.Wrap(err, "create source directory")
	}

	// Make directory for target image
	targetDir := filepath.Join(option.WorkDir, option.Target)
	if err := os.RemoveAll(targetDir); err != nil {
		return nil, err
	}

	converter := Converter{
		Option:    option,
		sourceDir: sourceDir,
		targetDir: targetDir,
	}

	return &converter, nil
}

// Convert source image to nydus(target) image
func (converter *Converter) Convert() error {
	// Init Nydus build cache
	var buildCache *cache.Cache
	if converter.BuildCache != "" {
		_cache, err := cache.New(cache.Opt{
			Ref:            converter.BuildCache,
			Insecure:       converter.BuildCacheInsecure,
			MaxRecords:     converter.BuildCacheMaxRecords,
			DockerV2Format: converter.DockerV2Format,
		})
		if err != nil {
			return errors.Wrap(err, "init build cache")
		}
		buildCache = _cache
	}

	// Init blob storage backend
	backend, err := blobbackend.NewBackend(
		converter.BackendType, converter.BackendConfig,
	)
	if err != nil {
		return errors.Wrap(err, "init blob backend")
	}

	// Init registry for pulling & pushing
	reg, err := registry.New(registry.RegistryOption{
		WorkDir:          converter.WorkDir,
		Source:           converter.Source,
		Target:           converter.Target,
		SourceInsecure:   converter.SourceInsecure,
		TargetInsecure:   converter.TargetInsecure,
		SignatureKeyPath: converter.SignatureKeyPath,
		MultiPlatform:    converter.MultiPlatform,
		DockerV2Format:   converter.DockerV2Format,

		Backend:    backend,
		BuildCache: buildCache,
	})
	if err != nil {
		return errors.Wrap(err, "init registry")
	}

	// Init build flow for Nydus building layer by layer
	buildFlow, err := nydus.NewBuildFlow(nydus.BuildFlowOption{
		SourceDir:      converter.sourceDir,
		TargetDir:      converter.targetDir,
		NydusImagePath: converter.NydusImagePath,
		PrefetchDir:    converter.PrefetchDir,
	})
	if err != nil {
		return errors.Wrap(err, "init build flow")
	}

	// Pull Nydus cache image from registry
	if err := reg.PullCache(); err != nil {
		logrus.Warnf("Pull cache image %s: %s", converter.BuildCache, err)
	}

	// Pull source layers
	if err = reg.Pull(func(
		layerJob *registry.LayerJob,
		parentBootstrapFunc func(string) (string, error),
	) error {
		// Start building once the layer has been pulled
		if err := buildFlow.Build(layerJob, parentBootstrapFunc); err != nil {
			return errors.Wrap(err, "build source layer")
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "pull source layer")
	}

	// Wait all layers to be built and pushed
	if err := buildFlow.Wait(); err != nil {
		return errors.Wrap(err, "build source layer")
	}

	// Push Nydus cache image
	if err := reg.PushCache(); err != nil {
		return errors.Wrap(err, "push cache image")
	}

	// Push target manifest or index
	if err := reg.PushManifest(); err != nil {
		return errors.Wrap(err, "push manifest")
	}

	// Write output info for debugging
	if err := reg.Output(); err != nil {
		return errors.Wrap(err, "output debug info")
	}

	logrus.Infof("Converted image %s to %s", converter.Source, converter.Target)

	return nil
}
