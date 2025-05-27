// Copyright 2022 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/containerd/containerd/v2/core/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type S3Backend struct {
	// objectPrefix is the path prefix of the uploaded object.
	// For example, if the blobID which should be uploaded is "abc",
	// and the objectPrefix is "path/to/my-registry/", then the object key will be
	// "path/to/my-registry/abc".
	objectPrefix       string
	bucketName         string
	endpointWithScheme string
	client             *s3.Client
}

type S3Config struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	Scheme          string `json:"scheme,omitempty"`
	BucketName      string `json:"bucket_name,omitempty"`
	Region          string `json:"region,omitempty"`
	ObjectPrefix    string `json:"object_prefix,omitempty"`
}

func newS3Backend(rawConfig []byte) (*S3Backend, error) {
	cfg := &S3Config{}
	if err := json.Unmarshal(rawConfig, cfg); err != nil {
		return nil, errors.Wrap(err, "parse S3 storage backend configuration")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "s3.amazonaws.com"
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}
	endpointWithScheme := fmt.Sprintf("%s://%s", cfg.Scheme, cfg.Endpoint)

	if cfg.BucketName == "" || cfg.Region == "" {
		return nil, fmt.Errorf("invalid S3 configuration: missing 'bucket_name' or 'region'")
	}

	s3AWSConfig, err := awscfg.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, errors.Wrap(err, "load default AWS config")
	}

	client := s3.NewFromConfig(s3AWSConfig, func(o *s3.Options) {
		o.BaseEndpoint = &endpointWithScheme
		o.Region = cfg.Region
		o.UsePathStyle = true
		if len(cfg.AccessKeySecret) > 0 && len(cfg.AccessKeyID) > 0 {
			o.Credentials = credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.AccessKeySecret, "")
		}
		o.UsePathStyle = true
	})

	return &S3Backend{
		objectPrefix:       cfg.ObjectPrefix,
		bucketName:         cfg.BucketName,
		endpointWithScheme: endpointWithScheme,
		client:             client,
	}, nil
}

func (b *S3Backend) Upload(ctx context.Context, blobID, blobPath string, size int64, forcePush bool) (*ocispec.Descriptor, error) {
	blobObjectKey := b.blobObjectKey(blobID)

	desc := blobDesc(size, blobID)
	desc.URLs = append(desc.URLs, b.remoteID(blobObjectKey))

	if !forcePush {
		if exist, err := b.existObject(ctx, blobObjectKey); err != nil {
			return nil, errors.Wrap(err, "check object existence")
		} else if exist {
			logrus.Infof("skip upload because blob exists: %s", blobID)
			return &desc, nil
		}
	}

	start := time.Now()

	blobFile, err := os.Open(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "open blob file")
	}
	defer blobFile.Close()

	uploader := manager.NewUploader(b.client, func(u *manager.Uploader) {
		u.PartSize = multipartChunkSize
	})
	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(b.bucketName),
		Key:               aws.String(blobObjectKey),
		Body:              blobFile,
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
	})
	if err != nil {
		return nil, errors.Wrap(err, "upload blob to s3 backend")
	}

	logrus.Debugf("uploaded blob %s to s3 backend, costs %s", blobObjectKey, time.Since(start))

	return &desc, nil
}

func (b *S3Backend) Finalize(_ bool) error {
	return nil
}

func (b *S3Backend) Check(blobID string) (bool, error) {
	return b.existObject(context.TODO(), b.blobObjectKey(blobID))
}

func (b *S3Backend) Type() Type {
	return S3backend
}

func (b *S3Backend) existObject(ctx context.Context, objectKey string) (bool, error) {
	_, err := b.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &b.bucketName,
		Key:    &objectKey,
	})
	if err != nil {
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *S3Backend) blobObjectKey(blobID string) string {
	return b.objectPrefix + blobID
}

type rangeReader struct {
	b         *S3Backend
	objectKey string
}

func (rr *rangeReader) Reader(offset int64, size int64) (io.ReadCloser, error) {
	output, err := rr.b.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &rr.b.bucketName,
		Key:    &rr.objectKey,
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", offset, offset+size-1)),
	})
	return output.Body, err
}

func (b *S3Backend) RangeReader(blobID string) (remotes.RangeReadCloser, error) {
	objectKey := b.blobObjectKey(blobID)
	return &rangeReader{b: b, objectKey: objectKey}, nil
}

func (b *S3Backend) Reader(blobID string) (io.ReadCloser, error) {
	objectKey := b.blobObjectKey(blobID)
	output, err := b.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &b.bucketName,
		Key:    &objectKey,
	})
	return output.Body, err
}

func (b *S3Backend) Size(blobID string) (int64, error) {
	objectKey := b.blobObjectKey(blobID)
	output, err := b.client.GetObjectAttributes(context.TODO(), &s3.GetObjectAttributesInput{
		Bucket: &b.bucketName,
		Key:    &objectKey,
	})
	if err != nil {
		return 0, errors.Wrap(err, "get object size")
	}
	return *output.ObjectSize, nil
}

func (b *S3Backend) remoteID(blobObjectKey string) string {
	remoteURL, _ := url.Parse(b.endpointWithScheme)
	remoteURL.Path = path.Join(remoteURL.Path, b.bucketName, blobObjectKey)
	return remoteURL.String()
}
