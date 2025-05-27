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
	"sync"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/containerd/containerd/v2/core/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	// For multipart uploads, OSS has a maximum number of 10000 chunks,
	// so we can only upload blob size of about 10000 * multipartChunkSize.
	multipartChunkSize = 200 * 1024 * 1024 /// 200MB
)

type multipartStatus struct {
	imur          *oss.InitiateMultipartUploadResult
	parts         []oss.UploadPart
	blobObjectKey string
	crc64Chan     chan uint64
	crc64ErrChan  chan error
}

type OSSBackend struct {
	// OSS storage does not support directory. Therefore add a prefix to each object
	// to make it a path-like object.
	objectPrefix string
	bucket       *oss.Bucket
	ms           []multipartStatus
	msMutex      sync.Mutex
}

func newOSSBackend(rawConfig []byte) (*OSSBackend, error) {
	var configMap map[string]string
	if err := json.Unmarshal(rawConfig, &configMap); err != nil {
		return nil, errors.Wrap(err, "Parse OSS storage backend configuration")
	}

	endpoint := configMap["endpoint"]
	bucketName := configMap["bucket_name"]

	// Below items are not mandatory
	accessKeyID := configMap["access_key_id"]
	accessKeySecret := configMap["access_key_secret"]
	objectPrefix := configMap["object_prefix"]

	if endpoint == "" || bucketName == "" {
		return nil, fmt.Errorf("invalid OSS configuration: missing 'endpoint' or 'bucket'")
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

// Upload blob as image layer to oss backend and verify
// integrity by calculate CRC64.
func (b *OSSBackend) Upload(_ context.Context, blobID, blobPath string, size int64, forcePush bool) (*ocispec.Descriptor, error) {
	blobObjectKey := b.objectPrefix + blobID

	desc := blobDesc(size, blobID)
	desc.URLs = append(desc.URLs, b.remoteID(blobID))

	if !forcePush {
		if exist, err := b.bucket.IsObjectExist(blobObjectKey); err != nil {
			return nil, errors.Wrap(err, "check object existence")
		} else if exist {
			logrus.Infof("skip upload because blob exists: %s", blobID)
			return &desc, nil
		}
	}

	start := time.Now()
	crc64Chan := make(chan uint64, 1)
	crc64ErrChan := make(chan error, 1)
	go func() {
		defer func() {
			close(crc64Chan)
			close(crc64ErrChan)
		}()
		crc64Val, e := calcCrc64ECMA(blobPath)
		crc64Chan <- crc64Val
		crc64ErrChan <- e
	}()

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

	ms := multipartStatus{
		imur:          &imur,
		parts:         parts,
		blobObjectKey: blobObjectKey,
		crc64Chan:     crc64Chan,
		crc64ErrChan:  crc64ErrChan,
	}
	b.msMutex.Lock()
	defer b.msMutex.Unlock()
	b.ms = append(b.ms, ms)

	logrus.Debugf("uploaded blob %s to oss backend, costs %s", blobObjectKey, time.Since(start))

	return &desc, nil
}

func (b *OSSBackend) Finalize(cancel bool) error {
	b.msMutex.Lock()
	defer b.msMutex.Unlock()

	for _, ms := range b.ms {
		if cancel {
			// If there is any failure during conversion process, it will
			// cause the uploaded blob to be left on oss, and these blobs
			// are hard to be GC-ed, so we need always to use the multipart
			// upload, and should call the `AbortMultipartUpload` method to
			// prevent blob residue as much as possible once any error happens
			// during conversion process.
			if err := b.bucket.AbortMultipartUpload(*ms.imur); err != nil {
				logrus.WithError(err).Warn("abort multipart upload")
			} else {
				logrus.Warnf("blob upload has been aborted: %s", ms.blobObjectKey)
			}
			continue
		}

		_, err := b.bucket.CompleteMultipartUpload(*ms.imur, ms.parts)
		if err != nil {
			return errors.Wrap(err, "complete multipart upload")
		}

		props, err := b.bucket.GetObjectDetailedMeta(ms.blobObjectKey)
		if err != nil {
			return errors.Wrapf(err, "get object meta")
		}

		// Try to validate blob object integrity if any crc64 value is returned.
		if value, ok := props[http.CanonicalHeaderKey("x-oss-hash-crc64ecma")]; ok {
			if len(value) == 1 {
				uploadedCrc, err := strconv.ParseUint(value[0], 10, 64)
				if err != nil {
					return errors.Wrapf(err, "parse uploaded crc64")
				}

				err = <-ms.crc64ErrChan
				if err != nil {
					return errors.Wrapf(err, "calculate crc64")
				}

				if crc64Val := <-ms.crc64Chan; uploadedCrc != crc64Val {
					return errors.Errorf("crc64 mismatch, uploaded=%d, expected=%d", uploadedCrc, crc64Val)
				}

			} else {
				logrus.Warnf("too many values, skip crc64 integrity check.")
			}
		} else {
			logrus.Warnf("no crc64 in header, skip crc64 integrity check.")
		}
	}

	return nil
}

func (b *OSSBackend) Check(blobID string) (bool, error) {
	blobID = b.objectPrefix + blobID
	return b.bucket.IsObjectExist(blobID)
}

func (b *OSSBackend) Type() Type {
	return OssBackend
}

type RangeReader struct {
	b      *OSSBackend
	blobID string
}

func (rr *RangeReader) Reader(offset int64, size int64) (io.ReadCloser, error) {
	return rr.b.bucket.GetObject(rr.blobID, oss.Range(offset, offset+size-1))
}

func (b *OSSBackend) RangeReader(blobID string) (remotes.RangeReadCloser, error) {
	blobID = b.objectPrefix + blobID
	return &RangeReader{b: b, blobID: blobID}, nil
}

func (b *OSSBackend) Reader(blobID string) (io.ReadCloser, error) {
	blobID = b.objectPrefix + blobID
	rc, err := b.bucket.GetObject(blobID)
	return rc, err
}

func (b *OSSBackend) Size(blobID string) (int64, error) {
	blobID = b.objectPrefix + blobID
	headers, err := b.bucket.GetObjectMeta(blobID)
	if err != nil {
		return 0, errors.Wrap(err, "get object size")
	}
	sizeStr := headers.Get("Content-Length")
	size, err := strconv.ParseInt(sizeStr, 10, 0)
	if err != nil {
		return 0, errors.Wrap(err, "parse content-length header")
	}
	return size, nil
}

func (b *OSSBackend) remoteID(blobID string) string {
	return fmt.Sprintf("oss://%s/%s%s", b.bucket.BucketName, b.objectPrefix, blobID)
}
