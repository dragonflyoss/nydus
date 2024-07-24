// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package packer

import (
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/stretchr/testify/require"
)

func TestS3BackendConfig(t *testing.T) {
	s3BackendConfig := &S3BackendConfig{
		Endpoint:        "s3.amazonaws.com",
		Scheme:          "https",
		AccessKeyID:     "testAK",
		AccessKeySecret: "testSK",
		Region:          "region1",
		BucketName:      "test",
		MetaPrefix:      "meta",
		BlobPrefix:      "blob",
	}
	_, err := backend.NewBackend("s3", s3BackendConfig.rawMetaBackendCfg(), nil)
	require.NoError(t, err)
	_, err = backend.NewBackend("s3", s3BackendConfig.rawBlobBackendCfg(), nil)
	require.NoError(t, err)
	require.Equal(t, "s3", s3BackendConfig.backendType())
}
