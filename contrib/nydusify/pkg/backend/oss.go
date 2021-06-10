// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	splitPartsCount = 4
	// Blob size bigger than 100MB, apply multiparts upload.
	multipartsUploadThreshold = 100 * 1024 * 1024
)

type OSSBackend struct {
	// OSS storage does not support directory. Therefore add a prefix to each object
	// to make it a path-like object.
	objectPrefix string
	bucket       *oss.Bucket
}

func newOSSBackend(rawConfig []byte) (*OSSBackend, error) {
	var configMap map[string]string
	if err := json.Unmarshal(rawConfig, &configMap); err != nil {
		return nil, errors.Wrap(err, "Parse OSS storage backend configuration")
	}

	endpoint, ok1 := configMap["endpoint"]
	bucketName, ok2 := configMap["bucket_name"]

	// Below items are not mandatory
	accessKeyID := configMap["access_key_id"]
	accessKeySecret := configMap["access_key_secret"]
	objectPrefix := configMap["object_prefix"]

	if !ok1 || !ok2 {
		return nil, fmt.Errorf("no endpoint or bucket is specified")
	}

	client, err := oss.New(endpoint, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, errors.Wrap(err, "Create client")
	}

	bucket, err := client.Bucket(bucketName)
	if err != nil {
		return nil, errors.Wrap(err, "Create bucket")
	}

	return &OSSBackend{
		objectPrefix: objectPrefix,
		bucket:       bucket,
	}, nil
}

// Upload blob as image layer to oss backend. Depending on blob's size, upload it
// by multiparts method or the normal method
func (b *OSSBackend) Upload(ctx context.Context, blobID, blobPath string, size int64) (*ocispec.Descriptor, error) {
	blobObjectKey := b.objectPrefix + blobID

	desc := blobDesc(size, blobID)

	if exist, err := b.bucket.IsObjectExist(blobObjectKey); err != nil {
		return nil, err
	} else if exist {
		return &desc, nil
	}

	var stat os.FileInfo
	stat, err := os.Stat(blobPath)
	if err != nil {
		return nil, err
	}
	blobSize := stat.Size()

	var needMultiparts bool = false
	// Blob size bigger than 100MB, apply multiparts upload.
	if blobSize >= multipartsUploadThreshold {
		needMultiparts = true
	}

	start := time.Now()

	if needMultiparts {
		logrus.Debugf("Upload %s using multiparts method", blobObjectKey)
		chunks, err := oss.SplitFileByPartNum(blobPath, splitPartsCount)
		if err != nil {
			return nil, err
		}

		imur, err := b.bucket.InitiateMultipartUpload(blobObjectKey)
		if err != nil {
			return nil, err
		}

		var parts []oss.UploadPart

		g := new(errgroup.Group)
		for _, chunk := range chunks {
			ck := chunk
			g.Go(func() error {
				p, err := b.bucket.UploadPartFromFile(imur, blobPath, ck.Offset, ck.Size, ck.Number)
				if err != nil {
					return err
				}
				// TODO: We don't verify data part MD5 from ETag right now.
				// But we can do it if we have to.
				parts = append(parts, p)
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			return nil, errors.Wrap(err, "Uploading parts failed")
		}

		_, err = b.bucket.CompleteMultipartUpload(imur, parts)
		if err != nil {
			return nil, err
		}
	} else {
		reader, err := os.Open(blobPath)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		err = b.bucket.PutObject(blobObjectKey, reader)
		if err != nil {
			return nil, err
		}
	}

	// With OSS backend, no blob has to be pushed to registry, but have to push to build cache.

	end := time.Now()
	elapsed := end.Sub(start)
	logrus.Debugf("Uploading blob %s costs %s", blobObjectKey, elapsed)

	return &desc, nil
}

func (b *OSSBackend) Check(blobID string) (bool, error) {
	blobID = b.objectPrefix + blobID
	return b.bucket.IsObjectExist(blobID)
}

func (r *OSSBackend) Type() BackendType {
	return OssBackend
}
