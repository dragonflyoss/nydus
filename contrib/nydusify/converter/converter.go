// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"os"
	"path/filepath"

	"github.com/gosuri/uiprogress"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/nydus"
	"contrib/nydusify/registry"
)

type Option struct {
	Source string
	Target string

	WorkDir          string
	PrefetchDir      string
	SignatureKeyPath string
	NydusImagePath   string
	MultiPlatform    bool
	Silent           bool
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
	if err := os.MkdirAll(sourceDir, 0666); err != nil {
		return nil, err
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
	if !converter.Silent {
		uiprogress.Start()
	}

	reg, err := registry.New(registry.RegistryOption{
		WorkDir: converter.WorkDir,
		Source:  converter.Source,
		Target:  converter.Target,
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
		return err
	}

	// Wait all layers to be built and pushed
	if err := buildFlow.Wait(); err != nil {
		return errors.Wrap(err, "build source layer")
	}

	// Push bootstrap layer
	if err := reg.PushBootstrapLayer(
		buildFlow.GetBootstrap(),
		converter.SignatureKeyPath,
	); err != nil {
		return err
	}

	// Push target manifest or index
	if err := reg.PushManifest(converter.MultiPlatform); err != nil {
		return err
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
