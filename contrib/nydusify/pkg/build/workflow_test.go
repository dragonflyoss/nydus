// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package build

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"
)

func newWorkflowForTest(t *testing.T) *Workflow {
	t.Helper()

	workflow, err := NewWorkflow(WorkflowOption{
		TargetDir:      t.TempDir(),
		NydusImagePath: "/usr/bin/nydus-image",
		FsVersion:      "6",
	})
	require.NoError(t, err)

	return workflow
}

func TestNewWorkflowErrors(t *testing.T) {
	targetDir := t.TempDir()
	blobsDir := filepath.Join(targetDir, "blobs")
	require.NoError(t, os.MkdirAll(blobsDir, 0o755))
	require.NoError(t, os.Chmod(targetDir, 0o555))
	defer os.Chmod(targetDir, 0o755)

	workflow, err := NewWorkflow(WorkflowOption{TargetDir: targetDir, NydusImagePath: "/usr/bin/nydus-image"})
	require.Nil(t, workflow)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Remove blob directory")

	targetFile := filepath.Join(t.TempDir(), "target-file")
	require.NoError(t, os.WriteFile(targetFile, []byte("x"), 0o644))

	workflow, err = NewWorkflow(WorkflowOption{TargetDir: targetFile, NydusImagePath: "/usr/bin/nydus-image"})
	require.Nil(t, workflow)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Remove blob directory")
}

func TestNewWorkflowSuccess(t *testing.T) {
	targetDir := t.TempDir()
	workflow, err := NewWorkflow(WorkflowOption{
		TargetDir:      targetDir,
		NydusImagePath: "/usr/bin/nydus-image",
		ChunkDict:      "/tmp/chunk.dict",
		FsVersion:      "6",
	})
	require.NoError(t, err)
	require.NotNil(t, workflow)
	require.Equal(t, filepath.Join(targetDir, "blobs"), workflow.blobsDir)
	require.Equal(t, `{"dir": "`+filepath.Join(targetDir, "blobs")+`"}`, workflow.backendConfig)
	require.NotNil(t, workflow.builder)
}

func TestWorkflowBuildBuilderRunFails(t *testing.T) {
	workflow := newWorkflowForTest(t)

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&Builder{}), "Run", func(_ *Builder, _ BuilderOption) error {
		return errors.New("builder failed")
	})
	defer patches.Reset()

	blobPath, err := workflow.Build("/tmp/layer", "overlayfs", "", "/tmp/bootstrap", false)
	require.Empty(t, blobPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "build layer /tmp/layer")
}

func TestWorkflowBuildLatestBlobErrors(t *testing.T) {
	workflow := newWorkflowForTest(t)

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&Builder{}), "Run", func(_ *Builder, option BuilderOption) error {
		return os.WriteFile(option.OutputJSONPath, []byte("not-json"), 0o644)
	})
	defer patches.Reset()

	blobPath, err := workflow.Build("/tmp/layer", "overlayfs", "", filepath.Join(t.TempDir(), "bootstrap.boot"), false)
	require.Empty(t, blobPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "get latest blob")
}

func TestWorkflowBuildEmptyAndDuplicateBlob(t *testing.T) {
	workflow := newWorkflowForTest(t)
	bootstrapPath := filepath.Join(t.TempDir(), "bootstrap.boot")

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&Builder{}), "Run", func(_ *Builder, option BuilderOption) error {
		payload, err := json.Marshal(debugJSON{Version: "builder-v1", Blobs: []string{"sha256-empty"}})
		if err != nil {
			return err
		}
		if err := os.WriteFile(option.OutputJSONPath, payload, 0o644); err != nil {
			return err
		}
		return os.WriteFile(option.BlobPath, nil, 0o644)
	})
	defer patches.Reset()

	blobPath, err := workflow.Build("/tmp/layer", "overlayfs", "", bootstrapPath, false)
	require.NoError(t, err)
	require.Empty(t, blobPath)
	require.Equal(t, "builder-v1", workflow.BuilderVersion)
	require.Equal(t, bootstrapPath, workflow.parentBootstrapPath)

	patches.Reset()
	patches = gomonkey.NewPatches()
	patches.ApplyMethod(reflect.TypeOf(&Builder{}), "Run", func(_ *Builder, option BuilderOption) error {
		payload, err := json.Marshal(debugJSON{Version: "builder-v2", Blobs: []string{"sha256-empty"}})
		if err != nil {
			return err
		}
		if err := os.WriteFile(option.OutputJSONPath, payload, 0o644); err != nil {
			return err
		}
		return os.WriteFile(option.BlobPath, []byte("blob-data"), 0o644)
	})
	defer patches.Reset()

	blobPath, err = workflow.Build("/tmp/layer-2", "overlayfs", bootstrapPath, filepath.Join(t.TempDir(), "next.boot"), true)
	require.NoError(t, err)
	require.Empty(t, blobPath)
	require.Equal(t, "builder-v2", workflow.BuilderVersion)
	// parentBootstrapPath should stay updated to the current bootstrap even when the blob digest repeats.
	require.Contains(t, workflow.parentBootstrapPath, "next.boot")

	patches.Reset()
	patches = gomonkey.NewPatches()
	patches.ApplyMethod(reflect.TypeOf(&Builder{}), "Run", func(_ *Builder, option BuilderOption) error {
		payload, err := json.Marshal(debugJSON{Version: "builder-v3", Blobs: []string{"sha256-digest"}})
		if err != nil {
			return err
		}
		if err := os.WriteFile(option.OutputJSONPath, payload, 0o644); err != nil {
			return err
		}
		return os.WriteFile(option.BlobPath, []byte("blob-data"), 0o644)
	})
	defer patches.Reset()

	blobPath, err = workflow.Build("/tmp/layer-3", "overlayfs", workflow.parentBootstrapPath, filepath.Join(t.TempDir(), "final.boot"), false)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(workflow.blobsDir, "sha256-digest"), blobPath)
	_, err = os.Stat(blobPath)
	require.NoError(t, err)
}
