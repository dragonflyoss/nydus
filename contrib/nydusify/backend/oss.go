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
	bucket   *oss.Bucket
	progress func(cur int)
}

func newOSSBackend(endpoint, bucket, accessKeyID, accessKeySecret string) (*OSSBackend, error) {
	client, err := oss.New(endpoint, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, errors.Wrap(err, "init oss backend")
	}

	_bucket, err := client.Bucket(bucket)
	if err != nil {
		return nil, errors.Wrap(err, "init oss backend")
	}

	return &OSSBackend{
		bucket: _bucket,
	}, nil
}

func (backend *OSSBackend) ProgressChanged(event *oss.ProgressEvent) {
	backend.progress(int(event.ConsumedBytes))
}

func (backend *OSSBackend) Put(blobID string, reader io.Reader, progress func(cur int)) error {
	exist, err := backend.bucket.IsObjectExist(blobID)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	backend.progress = progress
	return backend.bucket.PutObject(blobID, reader, oss.Progress(backend))
}
