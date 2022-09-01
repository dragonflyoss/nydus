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
	// We always use multipart upload for OSS, and limit the
	// multipart chunk size to 500MB.
	multipartChunkSize = 500 * 1024 * 1024
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
			return nil, errors.Wrap(err, "check object existence")
		} else if exist {
			logrus.Infof("skip upload because blob exists: %s", blobID)
			return &desc, nil
		}
	}

	start := time.Now()
	var crc64 uint64
	crc64ErrChan := make(chan error, 1)
	go func() {
		var e error
		crc64, e = calcCrc64ECMA(blobPath)
		crc64ErrChan <- e
	}()

	defer close(crc64ErrChan)

	logrus.Debugf("upload %s using multipart method", blobObjectKey)
	chunks, err := oss.SplitFileByPartSize(blobPath, multipartChunkSize)
	if err != nil {
		return nil, errors.Wrap(err, "split file by part size")
	}

	imur, err := b.bucket.InitiateMultipartUpload(blobObjectKey)
	if err != nil {
		return nil, errors.Wrap(err, "initiate multipart upload")
	}

	eg := new(errgroup.Group)
	partsChan := make(chan oss.UploadPart, len(chunks))
	for _, chunk := range chunks {
		ck := chunk
		eg.Go(func() error {
			p, err := b.bucket.UploadPartFromFile(imur, blobPath, ck.Offset, ck.Size, ck.Number)
			if err != nil {
				return errors.Wrap(err, "upload part from file")
			}
			partsChan <- p
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		close(partsChan)
		if err := b.bucket.AbortMultipartUpload(imur); err != nil {
			return nil, errors.Wrap(err, "abort multipart upload")
		}
		return nil, errors.Wrap(err, "upload parts")
	}
	close(partsChan)

	var parts []oss.UploadPart
	for p := range partsChan {
		parts = append(parts, p)
	}

	_, err = b.bucket.CompleteMultipartUpload(imur, parts)
	if err != nil {
		return nil, errors.Wrap(err, "complete multipart upload")
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
				return nil, errors.Errorf("crc64 mismatch, uploaded=%d, expected=%d", uploadedCrc, crc64)
			}

		} else {
			logrus.Warnf("too many values, skip crc64 integrity check.")
		}
	} else {
		logrus.Warnf("no crc64 in header, skip crc64 integrity check.")
	}

	logrus.Debugf("uploaded blob %s, costs %s", blobObjectKey, time.Since(start))

	return &desc, nil
}

func (b *OSSBackend) Check(blobID string) (bool, error) {
	blobID = b.objectPrefix + blobID
	return b.bucket.IsObjectExist(blobID)
}

func (b *OSSBackend) Type() Type {
	return OssBackend
}
