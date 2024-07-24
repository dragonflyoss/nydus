// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"encoding/json"
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestBlobDesc(t *testing.T) {
	desc := blobDesc(123456, "205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a")
	require.Equal(t, int64(123456), desc.Size)
	require.Equal(t, "sha256:205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a", desc.Digest.String())
	require.Equal(t, utils.MediaTypeNydusBlob, desc.MediaType)
	require.Equal(t, map[string]string{
		utils.LayerAnnotationUncompressed: "sha256:205eed24cbec29ad9cb4593a73168ef1803402370a82f7d51ce25646fc2f943a",
		utils.LayerAnnotationNydusBlob:    "true",
	}, desc.Annotations)
}

func TestNewBackend(t *testing.T) {
	ossConfigJSON := `
	{
		"bucket_name": "test",
		"endpoint": "region.oss.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob"
	}`
	require.True(t, json.Valid([]byte(ossConfigJSON)))
	backend, err := NewBackend("oss", []byte(ossConfigJSON), nil)
	require.NoError(t, err)
	require.Equal(t, OssBackend, backend.Type())

	s3ConfigJSON := `
	{
		"bucket_name": "test",
		"endpoint": "s3.amazonaws.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob",
		"scheme": "https",
		"region": "region1"
	}`
	require.True(t, json.Valid([]byte(s3ConfigJSON)))
	backend, err = NewBackend("s3", []byte(s3ConfigJSON), nil)
	require.NoError(t, err)
	require.Equal(t, S3backend, backend.Type())

	testRegistryRemote, err := provider.DefaultRemote("test", false)
	require.NoError(t, err)
	backend, err = NewBackend("registry", nil, testRegistryRemote)
	require.NoError(t, err)
	require.Equal(t, RegistryBackend, backend.Type())

	backend, err = NewBackend("errBackend", nil, testRegistryRemote)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported backend type")
	require.Nil(t, backend)
}
