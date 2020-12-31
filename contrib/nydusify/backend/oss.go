// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"io"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/pkg/errors"
)

type OSSBackend struct {
	objectPrefix string
	bucket       *oss.Bucket
}

func newOSSBackend(endpoint, bucket, objectPrefix, accessKeyID, accessKeySecret string) (*OSSBackend, error) {
	client, err := oss.New(endpoint, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, errors.Wrap(err, "init oss backend")
	}

	_bucket, err := client.Bucket(bucket)
	if err != nil {
		return nil, errors.Wrap(err, "init oss backend")
	}

	return &OSSBackend{
		objectPrefix: objectPrefix,
		bucket:       _bucket,
	}, nil
}

func (backend *OSSBackend) Put(blobID string, reader io.Reader) error {
	blobID = backend.objectPrefix + blobID
	exist, err := backend.bucket.IsObjectExist(blobID)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	return backend.bucket.PutObject(blobID, reader)
}
