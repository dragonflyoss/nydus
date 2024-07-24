// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
)

func tempS3Backend() *S3Backend {
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
	backend, _ := newS3Backend([]byte(s3ConfigJSON))
	return backend
}

func TestS3RemoteID(t *testing.T) {
	s3Backend := tempS3Backend()
	id := s3Backend.remoteID("111")
	require.Equal(t, "https://s3.amazonaws.com/test/111", id)
}

func TestBlobObjectKey(t *testing.T) {
	s3Backend := tempS3Backend()
	blobObjectKey := s3Backend.blobObjectKey("111")
	require.Equal(t, "blob111", blobObjectKey)
}

func TestNewS3Backend(t *testing.T) {
	s3ConfigJSON1 := `
	{
		"bucket_name": "test",
		"endpoint": "s3.amazonaws.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob",
		"scheme": "https",
		"region": "region1"
	}`
	require.True(t, json.Valid([]byte(s3ConfigJSON1)))
	backend, err := newS3Backend([]byte(s3ConfigJSON1))
	require.NoError(t, err)
	require.Equal(t, "blob", backend.objectPrefix)
	require.Equal(t, "test", backend.bucketName)
	require.Equal(t, "https://s3.amazonaws.com", backend.endpointWithScheme)
	require.Equal(t, "https://s3.amazonaws.com", *backend.client.Options().BaseEndpoint)
	testCredentials, err := backend.client.Options().Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	realCredentials, err := credentials.NewStaticCredentialsProvider("testAK", "testSK", "").Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, testCredentials, realCredentials)

	s3ConfigJSON2 := `
	{
		"bucket_name": "test",
		"endpoint": "s3.amazonaws.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob",
		"scheme": "https",
		"region": "region1",
	}`
	backend, err = newS3Backend([]byte(s3ConfigJSON2))
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse S3 storage backend configuration")
	require.Nil(t, backend)

	s3ConfigJSON3 := `
	{
		"bucket_name": "test",
		"endpoint": "",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob",
		"scheme": "",
		"region": "region1"
	}`
	require.True(t, json.Valid([]byte(s3ConfigJSON3)))
	backend, err = newS3Backend([]byte(s3ConfigJSON3))
	require.NoError(t, err)
	require.Equal(t, "blob", backend.objectPrefix)
	require.Equal(t, "test", backend.bucketName)
	require.Equal(t, "https://s3.amazonaws.com", backend.endpointWithScheme)
	testCredentials, err = backend.client.Options().Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	realCredentials, err = credentials.NewStaticCredentialsProvider("testAK", "testSK", "").Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, testCredentials, realCredentials)

	s3ConfigJSON4 := `
	{
		"bucket_name": "",
		"endpoint": "s3.amazonaws.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"object_prefix": "blob",
		"scheme": "https",
		"region": ""
	}`
	require.True(t, json.Valid([]byte(s3ConfigJSON4)))
	backend, err = newS3Backend([]byte(s3ConfigJSON4))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid S3 configuration: missing 'bucket_name' or 'region'")
	require.Nil(t, backend)
}
