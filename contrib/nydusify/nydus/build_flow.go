// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package nydus

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

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
	backendConfig       string
	parentBootstrapPath string
	blobPushWorker      *utils.WorkerPool
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
		return nil, err
	}

	bootstrapPath := filepath.Join(option.TargetDir, "bootstrap")
	backendConfig := fmt.Sprintf(`{"dir": "%s"}`, blobsDir)
	blobPushWorker := utils.NewWorkerPool(registry.LayerPushWorkerCount, registry.MethodPush)
	builder := NewBuilder(option.NydusImagePath)

	return &BuildFlow{
		BuildFlowOption:     option,
		bootstrapPath:       bootstrapPath,
		blobsDir:            blobsDir,
		blobPushWorker:      blobPushWorker,
		parentBootstrapPath: "",
		backendConfig:       backendConfig,
		builder:             builder,
	}, nil
}

func (build *BuildFlow) Build(layerJob *registry.LayerJob) error {
	layerJob.Progress.SetStatus(registry.StatusBuilding)

	hash, err := layerJob.SourceLayer.Digest()
	if err != nil {
		return err
	}
	hashStr := hash.String()
	layerDir := filepath.Join(layerJob.Source.WorkDir, hashStr)

	// Build nydus bootstrap and blob
	if build.parentBootstrapPath != "" {
		if err := os.Rename(build.bootstrapPath, build.parentBootstrapPath); err != nil {
			return err
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
		return errors.Wrap(err, fmt.Sprintf("build layer %s", hashStr))
	}

	if build.parentBootstrapPath == "" {
		build.parentBootstrapPath = filepath.Join(build.TargetDir, "bootstrap-parent")
	}

	// Push nydus blob layer
	blobPath, err := build.getLatestBlobPath()
	if err != nil {
		return errors.Wrap(err, "get latest blob")
	}
	if blobPath != "" {
		layerJob.SetTargetLayer(blobPath, "", registry.MediaTypeNydusBlob, map[string]string{
			registry.LayerAnnotationNydusBlob: "true",
		})
		return build.blobPushWorker.AddJob(layerJob)
	}

	return nil
}

func (build *BuildFlow) Wait() error {
	return build.blobPushWorker.Wait()
}

func (build *BuildFlow) GetBootstrap() string {
	return build.bootstrapPath
}
