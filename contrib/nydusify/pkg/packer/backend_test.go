// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package packer

import (
	"encoding/json"
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

func TestOssBackendConfig(t *testing.T) {
	ossCfg := &OssBackendConfig{
		Endpoint:        "oss.aliyuncs.com",
		AccessKeyID:     "testAK",
		AccessKeySecret: "testSK",
		BucketName:      "test-bucket",
		MetaPrefix:      "meta/",
		BlobPrefix:      "blob/",
	}

	metaCfg := ossCfg.rawMetaBackendCfg()
	require.NotNil(t, metaCfg)

	var metaMap map[string]string
	require.NoError(t, json.Unmarshal(metaCfg, &metaMap))
	require.Equal(t, "oss.aliyuncs.com", metaMap["endpoint"])
	require.Equal(t, "testAK", metaMap["access_key_id"])
	require.Equal(t, "testSK", metaMap["access_key_secret"])
	require.Equal(t, "test-bucket", metaMap["bucket_name"])
	require.Equal(t, "meta/", metaMap["object_prefix"])

	blobCfg := ossCfg.rawBlobBackendCfg()
	require.NotNil(t, blobCfg)

	var blobMap map[string]string
	require.NoError(t, json.Unmarshal(blobCfg, &blobMap))
	require.Equal(t, "blob/", blobMap["object_prefix"])

	require.Equal(t, "oss", ossCfg.backendType())
}

func TestOssBackendConfigEmptyFields(t *testing.T) {
	ossCfg := &OssBackendConfig{}
	metaCfg := ossCfg.rawMetaBackendCfg()
	require.NotNil(t, metaCfg)

	var metaMap map[string]string
	require.NoError(t, json.Unmarshal(metaCfg, &metaMap))
	require.Equal(t, "", metaMap["endpoint"])
	require.Equal(t, "", metaMap["object_prefix"])
}

func TestParseBackendConfigStringOSS(t *testing.T) {
	cfg := `{"endpoint":"oss.aliyuncs.com","access_key_id":"ak","access_key_secret":"sk","bucket_name":"bkt","meta_prefix":"m","blob_prefix":"b"}`
	bc, err := ParseBackendConfigString("oss", cfg)
	require.NoError(t, err)
	require.Equal(t, "oss", bc.backendType())
}

func TestParseBackendConfigStringS3(t *testing.T) {
	cfg := `{"endpoint":"s3.amazonaws.com","access_key_id":"ak","access_key_secret":"sk","bucket_name":"bkt","region":"us-east-1","meta_prefix":"m","blob_prefix":"b"}`
	bc, err := ParseBackendConfigString("s3", cfg)
	require.NoError(t, err)
	require.Equal(t, "s3", bc.backendType())
}

func TestParseBackendConfigStringUnsupported(t *testing.T) {
	_, err := ParseBackendConfigString("gcs", "{}")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported backend type")
}

func TestParseBackendConfigStringInvalid(t *testing.T) {
	_, err := ParseBackendConfigString("oss", "not json")
	require.Error(t, err)
}

func TestParseBackendConfigFile(t *testing.T) {
	_, err := ParseBackendConfig("oss", "/nonexistent/path")
	require.Error(t, err)
}

func TestS3BackendConfigMethods(t *testing.T) {
	cfg := &S3BackendConfig{
		Endpoint:        "s3.amazonaws.com",
		Scheme:          "https",
		AccessKeyID:     "ak",
		AccessKeySecret: "sk",
		Region:          "us-east-1",
		BucketName:      "bkt",
		MetaPrefix:      "meta/",
		BlobPrefix:      "blob/",
	}

	metaCfg := cfg.rawMetaBackendCfg()
	require.NotNil(t, metaCfg)
	var metaMap map[string]string
	require.NoError(t, json.Unmarshal(metaCfg, &metaMap))
	require.Equal(t, "s3.amazonaws.com", metaMap["endpoint"])
	require.Equal(t, "meta/", metaMap["object_prefix"])

	blobCfg := cfg.rawBlobBackendCfg()
	require.NotNil(t, blobCfg)
	var blobMap map[string]string
	require.NoError(t, json.Unmarshal(blobCfg, &blobMap))
	require.Equal(t, "blob/", blobMap["object_prefix"])
}
