// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd/archive/compression"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"lukechampine.com/blake3"
)

const SupportedOS = "linux"
const SupportedArch = runtime.GOARCH

const defaultRetryAttempts = 3
const defaultRetryInterval = time.Second * 2

const (
	PlatformArchAMD64 string = "amd64"
	PlatformArchARM64 string = "arm64"
)

type FsVersion int

const (
	V5 FsVersion = iota
	V6
)

// IsErrHTTPResponseToHTTPSClient returns whether err is
// "http: server gave HTTP response to HTTPS client"
func isErrHTTPResponseToHTTPSClient(err error) bool {
	// The error string is unexposed as of Go 1.16, so we can't use `errors.Is`.
	// https://github.com/golang/go/issues/44855
	const unexposed = "server gave HTTP response to HTTPS client"
	return strings.Contains(err.Error(), unexposed)
}

// IsErrConnectionRefused return whether err is
// "connect: connection refused"
func isErrConnectionRefused(err error) bool {
	const errMessage = "connect: connection refused"
	return strings.Contains(err.Error(), errMessage)
}

func GetNydusFsVersionOrDefault(annotations map[string]string, defaultVersion FsVersion) FsVersion {
	if annotations == nil {
		return defaultVersion
	}
	if v, ok := annotations[LayerAnnotationNydusFsVersion]; ok {
		if v == "5" {
			return V5
		}
		if v == "6" {
			return V6
		}
	}

	return defaultVersion
}

func WithRetry(op func() error) error {
	var err error
	attempts := defaultRetryAttempts
	for attempts > 0 {
		attempts--
		if err != nil {
			if RetryWithHTTP(err) {
				return err
			}
			logrus.Warnf("Retry due to error: %s", err)
			time.Sleep(defaultRetryInterval)
		}
		if err = op(); err == nil {
			break
		}
	}
	return err
}

func RetryWithHTTP(err error) bool {
	return err != nil && (isErrHTTPResponseToHTTPSClient(err) || isErrConnectionRefused(err))
}

func MarshalToDesc(data interface{}, mediaType string) (*ocispec.Descriptor, []byte, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	dataDigest := digest.FromBytes(bytes)
	desc := ocispec.Descriptor{
		Digest:    dataDigest,
		Size:      int64(len(bytes)),
		MediaType: mediaType,
	}

	return &desc, bytes, nil
}

func IsNydusPlatform(platform *ocispec.Platform) bool {
	if platform != nil && platform.OSFeatures != nil {
		for _, key := range platform.OSFeatures {
			if key == ManifestOSFeatureNydus {
				return true
			}
		}
	}
	return false
}

func IsSupportedArch(arch string) bool {
	if arch != PlatformArchAMD64 && arch != PlatformArchARM64 {
		return false
	}
	return true
}

// A matched nydus image should match os/arch
func MatchNydusPlatform(dst *ocispec.Descriptor, os, arch string) bool {

	if dst.Platform.Architecture != arch || dst.Platform.OS != os {
		return false
	}

	if dst.Platform.OSFeatures == nil {
		return false
	}

	for _, feature := range dst.Platform.OSFeatures {
		if feature == ManifestOSFeatureNydus {
			return true
		}
	}

	return false
}

func UnpackFile(reader io.Reader, source, target string) error {
	rdr, err := compression.DecompressStream(reader)
	if err != nil {
		return err
	}
	defer rdr.Close()

	found := false
	tr := tar.NewReader(rdr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		if hdr.Name == source {
			file, err := os.Create(target)
			if err != nil {
				return err
			}
			defer file.Close()
			if _, err := io.Copy(file, tr); err != nil {
				return err
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Not found file %s in targz", source)
	}

	return nil
}

func IsEmptyString(str string) bool {
	return strings.TrimSpace(str) == ""
}

func IsPathExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func HashFile(path string) ([]byte, error) {
	hasher := blake3.New(32, nil)

	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "open file before hashing file")
	}
	defer file.Close()

	buf := make([]byte, 2<<15) // 64KB
	for {
		n, err := file.Read(buf)
		if err == io.EOF || n == 0 {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "read file during hashing file")
		}
		if _, err := hasher.Write(buf); err != nil {
			return nil, errors.Wrap(err, "calculate hash of file")
		}
	}

	return hasher.Sum(nil), nil
}
