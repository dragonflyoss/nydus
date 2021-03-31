// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package build

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type WorkflowOption struct {
	TargetDir      string
	NydusImagePath string
	PrefetchDir    string
}

type Workflow struct {
	WorkflowOption
	bootstrapPath       string
	blobsDir            string
	backendConfig       string
	parentBootstrapPath string
	builder             *Builder
	lastBlobID          string
}

type debugJSON struct {
	Blobs []string
}

// Dump output json file of every layer to $workdir/bootstraps directory
// for debug or perf analysis purpose
func (workflow *Workflow) buildOutputJSONPath() string {
	return workflow.bootstrapPath + "-output.json"
}

// Get latest built blob from blobs directory
func (workflow *Workflow) getLatestBlobPath() (string, error) {
	var data debugJSON
	jsonBytes, err := ioutil.ReadFile(workflow.buildOutputJSONPath())
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return "", err
	}
	blobIDs := data.Blobs

	if len(blobIDs) == 0 {
		return "", nil
	}

	latestBlobID := blobIDs[len(blobIDs)-1]
	if latestBlobID != workflow.lastBlobID {
		workflow.lastBlobID = latestBlobID
		blobPath := filepath.Join(workflow.blobsDir, latestBlobID)
		return blobPath, nil
	}

	return "", nil
}

// NewWorkflow prepare bootstrap and blobs path for layered build workflow
func NewWorkflow(option WorkflowOption) (*Workflow, error) {
	blobsDir := filepath.Join(option.TargetDir, "blobs")
	if err := os.RemoveAll(blobsDir); err != nil {
		return nil, errors.Wrap(err, "Remove blob directory")
	}
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return nil, errors.Wrap(err, "Create blob directory")
	}

	backendConfig := fmt.Sprintf(`{"dir": "%s"}`, blobsDir)
	builder := NewBuilder(option.NydusImagePath)

	if option.PrefetchDir == "" {
		option.PrefetchDir = "/"
	}

	return &Workflow{
		WorkflowOption: option,
		blobsDir:       blobsDir,
		backendConfig:  backendConfig,
		builder:        builder,
	}, nil
}

// Build nydus bootstrap and blob, returned blobPath's basename is sha256 hex string
func (workflow *Workflow) Build(
	layerDir, whiteoutSpec, parentBootstrapPath, bootstrapPath string,
) (string, error) {
	workflow.bootstrapPath = bootstrapPath

	if parentBootstrapPath != "" {
		workflow.parentBootstrapPath = parentBootstrapPath
	}

	blobPath := filepath.Join(workflow.blobsDir, uuid.NewString())

	if err := workflow.builder.Run(BuilderOption{
		ParentBootstrapPath: workflow.parentBootstrapPath,
		BootstrapPath:       workflow.bootstrapPath,
		RootfsPath:          layerDir,
		PrefetchDir:         workflow.PrefetchDir,
		WhiteoutSpec:        whiteoutSpec,
		OutputJSONPath:      workflow.buildOutputJSONPath(),
		BlobPath:            blobPath,
	}); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("build layer %s", layerDir))
	}

	workflow.parentBootstrapPath = workflow.bootstrapPath

	digestedBlobPath, err := workflow.getLatestBlobPath()
	if err != nil {
		return "", errors.Wrap(err, "get latest blob")
	}

	logrus.Debugf("original: %s. digested: %s", blobPath, digestedBlobPath)

	// Rename the newly generated blob to its sha256 digest.
	// Because the flow will use the basename as the blob object to be pushed to registry.
	// When `digestedBlobPath` is void, this layer's bootsrap can be pushed meanwhile not for blob
	if digestedBlobPath != "" {
		err = os.Rename(blobPath, digestedBlobPath)
		if err != nil {
			return "", err
		}
	}

	return digestedBlobPath, nil
}
