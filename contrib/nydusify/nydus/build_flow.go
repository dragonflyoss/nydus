// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package nydus

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"

	"contrib/nydusify/registry"
	"contrib/nydusify/utils"
)

type BuildFlowOption struct {
	SourceDir      string
	TargetDir      string
	NydusImagePath string
	PrefetchDir    string
}

type BuildFlow struct {
	BuildFlowOption
	bootstrapPath       string
	blobsDir            string
	bootstrapsDir       string
	backendConfig       string
	parentBootstrapPath string
	layerPushWorker     *utils.WorkerPool
	builder             *Builder
	blobIDs             []string
}

func (build *BuildFlow) getLatestBlobPath() (string, error) {
	blobs, err := ioutil.ReadDir(build.blobsDir)
	if err != nil {
		return "", err
	}

	for _, blobPath := range blobs {
		blobID := blobPath.Name()
		exist := false
		for _, existBlobID := range build.blobIDs {
			if existBlobID == blobID {
				exist = true
				break
			}
		}
		if !exist {
			build.blobIDs = append(build.blobIDs, blobID)
			return filepath.Join(build.blobsDir, blobID), nil
		}
	}

	return "", nil
}

func NewBuildFlow(option BuildFlowOption) (*BuildFlow, error) {
	// Prepare bootstrap and blobs path for build
	blobsDir := filepath.Join(option.TargetDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0770); err != nil {
		return nil, errors.Wrap(err, "create blob directory")
	}

	bootstrapsDir := filepath.Join(option.TargetDir, "bootstraps")
	if err := os.MkdirAll(bootstrapsDir, 0770); err != nil {
		return nil, errors.Wrap(err, "create bootstrap directory")
	}
	bootstrapPath := filepath.Join(bootstrapsDir, "bootstrap")

	backendConfig := fmt.Sprintf(`{"dir": "%s"}`, blobsDir)
	layerPushWorker := utils.NewWorkerPool(registry.LayerPushWorkerCount, registry.MethodPush)
	builder := NewBuilder(option.NydusImagePath)

	return &BuildFlow{
		BuildFlowOption:     option,
		bootstrapPath:       bootstrapPath,
		blobsDir:            blobsDir,
		bootstrapsDir:       bootstrapsDir,
		layerPushWorker:     layerPushWorker,
		parentBootstrapPath: "",
		backendConfig:       backendConfig,
		builder:             builder,
	}, nil
}

func (build *BuildFlow) Build(layerJob *registry.LayerJob, pullParentBootstrap func(string) (string, error)) error {
	layerDigest, err := layerJob.SourceLayer.Digest()
	if err != nil {
		return errors.Wrap(err, "get source layer digest")
	}
	layerDir := filepath.Join(layerJob.Source.WorkDir, layerDigest.String())

	if layerJob.Parent != nil && layerJob.Parent.Cached {
		// If parent layer hits cache record, use the bootstrap layer
		// recorded in the cache as the parent bootstrap of current layer
		build.parentBootstrapPath, err = pullParentBootstrap(build.bootstrapsDir)
		if err != nil {
			return errors.Wrap(err, "pull parent bootstrap")
		}
	}

	if err := build.builder.Run(BuilderOption{
		ParentBootstrapPath: build.parentBootstrapPath,
		BootstrapPath:       build.bootstrapPath,
		RootfsPath:          layerDir,
		BackendType:         "localfs",
		BackendConfig:       build.backendConfig,
		PrefetchDir:         build.PrefetchDir,
	}); err != nil {
		return errors.Wrap(err, fmt.Sprintf("build layer %s", layerDigest))
	}

	blobPath, err := build.getLatestBlobPath()
	if err != nil {
		return errors.Wrap(err, "get latest blob")
	}

	parentBootstrapPath := filepath.Join(build.bootstrapsDir, layerJob.SourceLayerChainID.String())
	if err := os.Rename(build.bootstrapPath, parentBootstrapPath); err != nil {
		return errors.Wrap(err, "rename bootstrap to parent bootstrap")
	}
	build.parentBootstrapPath = parentBootstrapPath

	// Push nydus blob layer
	if blobPath != "" {
		layerJob.SetTargetBlobLayer(blobPath, "", utils.MediaTypeNydusBlob)
	}

	// TODO: bootstrap layer signature
	layerJob.SetTargetBootstrapLayer(
		parentBootstrapPath, utils.BootstrapFileNameInLayer, types.OCILayer,
	)

	return build.layerPushWorker.AddJob(layerJob)
}

func (build *BuildFlow) Wait() error {
	return build.layerPushWorker.Wait()
}
