// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"os"
	"path/filepath"

	"github.com/gosuri/uiprogress"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	blobbackend "contrib/nydusify/backend"
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
	Silent           bool

	BackendType   string
	BackendConfig string
}

type Converter struct {
	Option
	backend   blobbackend.Backend
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

	// Parse blob storage backend config
	backend, err := blobbackend.NewBackend(option.BackendType, option.BackendConfig)
	if err != nil {
		return nil, errors.Wrap(err, "init blob backend")
	}

	converter := Converter{
		Option:    option,
		backend:   backend,
		sourceDir: sourceDir,
		targetDir: targetDir,
	}

	return &converter, nil
}

// Convert source image to nydus(target) image
func (converter *Converter) Convert() error {
	if !converter.Silent {
		uiprogress.Start()
	}

	reg, err := registry.New(registry.RegistryOption{
		WorkDir:        converter.WorkDir,
		Source:         converter.Source,
		Target:         converter.Target,
		SourceInsecure: converter.SourceInsecure,
		TargetInsecure: converter.TargetInsecure,
		Backend:        converter.backend,
	})
	if err != nil {
		return err
	}

	buildFlow, err := nydus.NewBuildFlow(nydus.BuildFlowOption{
		SourceDir:      converter.sourceDir,
		TargetDir:      converter.targetDir,
		NydusImagePath: converter.NydusImagePath,
		PrefetchDir:    converter.PrefetchDir,
	})
	if err != nil {
		return err
	}

	// Pull source layers
	if err = reg.Pull(func(layerJob *registry.LayerJob) error {
		// Start building once the layer has been pulled
		return buildFlow.Build(layerJob)
	}); err != nil {
		return errors.Wrap(err, "pull source layer")
	}

	// Wait all layers to be built and pushed
	if err := buildFlow.Wait(); err != nil {
		return errors.Wrap(err, "build source layer")
	}

	// Push bootstrap layer
	if err := reg.PushBootstrapLayer(
		buildFlow.GetBootstrap(),
		buildFlow.GetBlobIDs(),
		converter.SignatureKeyPath,
	); err != nil {
		return errors.Wrap(err, "push bootstrap layer")
	}

	// Push target manifest or index
	if err := reg.PushManifest(converter.MultiPlatform); err != nil {
		return errors.Wrap(err, "push manifest")
	}

	if !converter.Silent {
		uiprogress.Stop()
	}

	logrus.Infof(
		"Success convert image %s to %s",
		converter.Source,
		converter.Target,
	)

	return nil
}
