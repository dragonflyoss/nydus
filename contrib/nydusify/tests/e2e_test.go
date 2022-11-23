// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func testBasicConvert(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)
	registry.Build(t, "image-basic")
	nydusify := NewNydusify(registry, "image-basic", "image-basic-nydus", "", "", fsVersion)
	nydusify.Convert(t)
	nydusify.Check(t)
}

func testBasicAuth(t *testing.T, fsVersion string) {
	registry := NewAuthRegistry(t)
	defer registry.Destroy(t)
	registry.AuthBuild(t, "image-basic")
	nydusify := NewNydusify(registry, "image-basic", "image-basic-nydus", "", "", fsVersion)
	nydusify.Convert(t)
	nydusify.Check(t)
}

func testReproducableBuild(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	registry.Build(t, "image-basic")
	defer registry.Destroy(t)
	var initBootstraHash []byte
	// Build the same image repeatedly to verify that the bootstarp files are the same
	for i := 0; i < 5; i++ {
		workDir := fmt.Sprintf("./tmp-%d", i)
		os.Setenv("WORKDIR", workDir)
		nydusify := NewNydusify(registry, "image-basic", "image-basic-nydus", "", "", fsVersion)
		nydusify.Convert(t)
		nydusify.Check(t)
		hash, err := utils.HashFile(nydusify.GetBootstarpFilePath())
		if err != nil {
			t.Fatalf("expect bootstrap file must exist, but actual is not, error: %s", err)
		}
		if len(initBootstraHash) == 0 {
			initBootstraHash = hash
		} else {
			assert.Equal(t, initBootstraHash, hash)
		}
	}
}

func testConvertWithCache(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)

	registry.Build(t, "image-basic")
	nydusify1 := NewNydusify(registry, "image-basic", "image-basic-nydus-1", "cache:v1", "", fsVersion)
	nydusify1.Convert(t)
	nydusify1.Check(t)
	nydusify2 := NewNydusify(registry, "image-basic", "image-basic-nydus-2", "cache:v1", "", fsVersion)
	nydusify2.Convert(t)
	nydusify2.Check(t)

	registry.Build(t, "image-from-1")
	nydusify3 := NewNydusify(registry, "image-from-1", "image-from-nydus-1", "cache:v1", "", fsVersion)
	nydusify3.Convert(t)
	nydusify3.Check(t)

	registry.Build(t, "image-from-2")
	nydusify4 := NewNydusify(registry, "image-from-2", "image-from-nydus-2", "cache:v1", "", fsVersion)
	nydusify4.Convert(t)
	nydusify4.Check(t)
}

func testConvertWithChunkDict(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)

	registry.Build(t, "chunk-dict-1")
	// build chunk-dict-1 bootstrap
	nydusify1 := NewNydusify(registry, "chunk-dict-1", "nydus:chunk-dict-1", "", "", fsVersion)
	nydusify1.Convert(t)
	nydusify1.Check(t)
	chunkDictOpt := fmt.Sprintf("bootstrap:registry:%s/%s", registry.Host(), "nydus:chunk-dict-1")
	// build without build-cache
	registry.Build(t, "image-basic")
	nydusify2 := NewNydusify(registry, "image-basic", "nydus:image-basic", "", chunkDictOpt, fsVersion)
	nydusify2.Convert(t)
	nydusify2.Check(t)
	// build with build-cache
	registry.Build(t, "image-from-1")
	nydusify3 := NewNydusify(registry, "image-from-1", "nydus:image-from-1", "nydus:cache_v1", chunkDictOpt, fsVersion)
	nydusify3.Convert(t)
	nydusify3.Check(t)
	// change chunk dict
	registry.Build(t, "chunk-dict-2")
	nydusify4 := NewNydusify(registry, "chunk-dict-2", "nydus:chunk-dict-2", "", "", fsVersion)
	nydusify4.Convert(t)
	nydusify4.Check(t)
	chunkDictOpt = fmt.Sprintf("bootstrap:registry:%s/%s", registry.Host(), "nydus:chunk-dict-2")
	registry.Build(t, "image-from-2")
	nydusify5 := NewNydusify(registry, "image-from-2", "nydus:image-from-2", "nydus:cache_v1", chunkDictOpt, fsVersion)
	nydusify5.Convert(t)
	nydusify5.Check(t)
}

func testConvertWithS3Backend(t *testing.T, fsVersion string) {
	registry := NewRegistry(t)
	defer registry.Destroy(t)
	registry.Build(t, "image-basic")

	// set up a minio server to mock s3 service
	accessKey := "minio"
	accessSecret := "minio123"
	region := "us-east-1"
	bucketName := "nydus"
	minioPort := 9000
	minioContainerName := "minio"
	minioDataDir := "/tmp/minio-data"
	endpoint := fmt.Sprintf("http://localhost:%d", minioPort)
	createMinioContainerCmd := fmt.Sprintf(`
		docker run -p %d:9000 -d -v %s:/data \
	    	-e "MINIO_ACCESS_KEY=%s" \
	    	-e "MINIO_SECRET_KEY=%s" \
	  		-e "MINIO_REGION=%s" \
			--name %s minio/minio server /data`,
		minioPort, minioDataDir, accessKey, accessSecret, region, minioContainerName)
	if err := os.MkdirAll(minioDataDir, 0755); err != nil {
		t.Fatalf("failed to create minio data dir: %s", err)
	}
	defer os.RemoveAll(minioDataDir)
	run(t, createMinioContainerCmd, false)
	defer run(t, fmt.Sprintf("docker rm -f %s", minioContainerName), false)

	// wait for the minio container to be up
	time.Sleep(5 * time.Second)

	// create bucket
	s3Client := s3.NewFromConfig(aws.Config{}, func(o *s3.Options) {
		o.EndpointResolver = s3.EndpointResolverFromURL(endpoint)
		o.Region = region
		o.UsePathStyle = true
		o.Credentials = credentials.NewStaticCredentialsProvider(accessKey, accessSecret, "")
		o.UsePathStyle = true
	})
	createBucketInput := s3.CreateBucketInput{Bucket: &bucketName}
	_, err := s3Client.CreateBucket(context.TODO(), &createBucketInput)
	if err != nil {
		t.Fatalf(err.Error())

	}
	logrus.Infof("create s3 backend bucket %s", bucketName)

	s3Config := &backend.S3Config{
		AccessKeyID:     accessKey,
		AccessKeySecret: accessSecret,
		Endpoint:        endpoint,
		BucketName:      bucketName,
		Region:          region,
		ObjectPrefix:    "path/to/registry",
	}
	s3ConfigBytes, err := json.Marshal(s3Config)
	if err != nil {
		t.Fatalf("marshal s3 config failed: %v", err)
	}

	originalBackendConfig := os.Getenv("BACKEND_CONFIG")
	backendConfig := string(s3ConfigBytes)
	if err := os.Setenv("BACKEND_CONFIG", backendConfig); err != nil {
		t.Fatalf("set env BACKEND_CONFIG failed: %v", err)
	}
	defer os.Setenv("BACKEND_CONFIG", originalBackendConfig)

	originalBackendType := os.Getenv("BACKEND_TYPE")
	if err := os.Setenv("BACKEND_TYPE", "s3"); err != nil {
		t.Fatalf("set env BACKEND_TYPE failed: %v", err)
	}
	defer os.Setenv("BACKEND_TYPE", originalBackendType)

	logrus.Infof("use s3 backend config: %s", backendConfig)

	nydusify := NewNydusify(registry, "image-basic", "image-basic-nydus", "", "", fsVersion)
	nydusify.Convert(t)
	// TODO nydusd doesn't support s3 backend for now, skip the checker
	// nydusify.Check(t)
}

func TestSmoke(t *testing.T) {
	fsVersions := [2]string{"5", "6"}
	for _, v := range fsVersions {
		testBasicAuth(t, v)
		testBasicConvert(t, v)
		testReproducableBuild(t, v)
		testConvertWithCache(t, v)
		testConvertWithChunkDict(t, v)
		testConvertWithS3Backend(t, v)
	}
}
