// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package packer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArtifactPath(t *testing.T) {
	artifact, err := NewArtifact("")
	defer os.RemoveAll("./.nydus-build-output")
	require.NoError(t, err)
	require.Equal(t, ".nydus-build-output/test.meta", artifact.bootstrapPath("test.meta"))
	require.Equal(t, ".nydus-build-output/test.m", artifact.bootstrapPath("test.m"))
	require.Equal(t, ".nydus-build-output/test.meta", artifact.bootstrapPath("test"))
	require.Equal(t, ".nydus-build-output/test.blob", artifact.blobFilePath("test.meta", false))
	require.Equal(t, ".nydus-build-output/test.blob", artifact.blobFilePath("test.m", false))
	require.Equal(t, ".nydus-build-output/test.blob", artifact.blobFilePath("test", false))
	require.Equal(t, ".nydus-build-output/test", artifact.blobFilePath("test", true))

	artifact, err = NewArtifact("/tmp")
	require.NoError(t, err)
	require.Equal(t, "/tmp/test.meta", artifact.bootstrapPath("test.meta"))
	require.Equal(t, "/tmp/test.m", artifact.bootstrapPath("test.m"))
	require.Equal(t, "/tmp/test.meta", artifact.bootstrapPath("test"))
	require.Equal(t, "/tmp/test.blob", artifact.blobFilePath("test.meta", false))
	require.Equal(t, "/tmp/test.blob", artifact.blobFilePath("test.m", false))
	require.Equal(t, "/tmp/test.blob", artifact.blobFilePath("test", false))
	require.Equal(t, "/tmp/test", artifact.blobFilePath("test", true))
}
