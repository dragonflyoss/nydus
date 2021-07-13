// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc64"
	"io"
	"net/http"
	"os"
	"strconv"
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

func calcCrc64ECMA(path string) (uint64, error) {
	buf := make([]byte, 4*1024)
	table := crc64.MakeTable(crc64.ECMA)

	f, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrapf(err, "calc md5sum")
	}
	defer f.Close()

	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return 0, err
	}
	blobCrc64 := crc64.Checksum(buf[:n], table)

	for {
		n, err := f.Read(buf)
		blobCrc64 = crc64.Update(blobCrc64, table, buf[:n])
		if err == io.EOF || n == 0 {
			break
		}
	}

	return blobCrc64, nil
}

// Upload blob as image layer to oss backend.
// Depending on blob's size, upload it by multiparts method or the normal method.
// Verify integrity by calculate  CRC64.
func (b *OSSBackend) Upload(ctx context.Context, blobID, blobPath string, size int64, forcePush bool) (*ocispec.Descriptor, error) {
	blobObjectKey := b.objectPrefix + blobID

	desc := blobDesc(size, blobID)

	if !forcePush {
		if exist, err := b.bucket.IsObjectExist(blobObjectKey); err != nil {
			return nil, err
		} else if exist {
			logrus.Infof("Skip upload because blob exists: %s", blobID)
			return &desc, nil
		}
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
	var crc64 uint64 = 0
	crc64ErrChan := make(chan error, 1)
	go func() {
		var e error
		crc64, e = calcCrc64ECMA(blobPath)
		crc64ErrChan <- e
	}()

	defer close(crc64ErrChan)

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

		// It always splits the blob into splitPartsCount=4 parts
		partsChan := make(chan oss.UploadPart, splitPartsCount)

		g := new(errgroup.Group)
		for _, chunk := range chunks {
			ck := chunk
			g.Go(func() error {
				p, err := b.bucket.UploadPartFromFile(imur, blobPath, ck.Offset, ck.Size, ck.Number)
				if err != nil {
					return err
				}
				partsChan <- p
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			b.bucket.AbortMultipartUpload(imur)
			close(partsChan)
			return nil, errors.Wrap(err, "Uploading parts failed")
		}

		close(partsChan)

		var parts []oss.UploadPart
		for p := range partsChan {
			parts = append(parts, p)
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

	props, err := b.bucket.GetObjectDetailedMeta(blobObjectKey)
	if err != nil {
		return nil, errors.Wrapf(err, "get object meta")
	}

	// Try to validate blob object integrity if any crc64 value is returned.
	if value, ok := props[http.CanonicalHeaderKey("x-oss-hash-crc64ecma")]; ok {
		if len(value) == 1 {
			uploadedCrc, err := strconv.ParseUint(value[0], 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "parse uploaded crc64")
			}

			err = <-crc64ErrChan
			if err != nil {
				return nil, errors.Wrapf(err, "calculate crc64")
			}

			if uploadedCrc != crc64 {
				return nil, errors.Errorf("CRC64 mismatch. Uploaded=%d, expected=%d", uploadedCrc, crc64)
			}

		} else {
			logrus.Warnf("Too many values, skip crc64 integrity check.")
		}
	} else {
		logrus.Warnf("No CRC64 in header, skip crc64 integrity check.")
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
