// Copyright 2022 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The Nydusify CLI tool converts an OCI container image from source registry into
// a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to
// target registry.

package packer

import (
	"encoding/json"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
)

type BackendConfig interface {
	rawMetaBackendCfg() []byte
	rawBlobBackendCfg() []byte
	backendType() string
}

type OssBackendConfig struct {
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	BucketName      string `json:"bucket_name"`
	MetaPrefix      string `json:"meta_prefix"`
	BlobPrefix      string `json:"blob_prefix"`
}

func (cfg *OssBackendConfig) rawMetaBackendCfg() []byte {
	configMap := map[string]string{
		"endpoint":          cfg.Endpoint,
		"access_key_id":     cfg.AccessKeyID,
		"access_key_secret": cfg.AccessKeySecret,
		"bucket_name":       cfg.BucketName,
		"object_prefix":     cfg.MetaPrefix,
	}
	b, _ := json.Marshal(configMap)
	return b
}

func (cfg *OssBackendConfig) rawBlobBackendCfg() []byte {
	configMap := map[string]string{
		"endpoint":          cfg.Endpoint,
		"access_key_id":     cfg.AccessKeyID,
		"access_key_secret": cfg.AccessKeySecret,
		"bucket_name":       cfg.BucketName,
		"object_prefix":     cfg.BlobPrefix,
	}
	b, _ := json.Marshal(configMap)
	return b
}

func (cfg *OssBackendConfig) backendType() string {
	return "oss"
}

type S3BackendConfig struct {
	Endpoint        string `json:"endpoint"`
	Scheme          string `json:"scheme,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	Region          string `json:"region"`
	BucketName      string `json:"bucket_name"`
	MetaPrefix      string `json:"meta_prefix"`
	BlobPrefix      string `json:"blob_prefix"`
}

func (cfg *S3BackendConfig) rawMetaBackendCfg() []byte {
	s3Config := backend.S3Config{
		AccessKeyID:     cfg.AccessKeyID,
		AccessKeySecret: cfg.AccessKeySecret,
		Endpoint:        cfg.Endpoint,
		Scheme:          cfg.Scheme,
		BucketName:      cfg.BucketName,
		Region:          cfg.Region,
		ObjectPrefix:    cfg.MetaPrefix,
	}
	b, _ := json.Marshal(s3Config)
	return b
}

func (cfg *S3BackendConfig) rawBlobBackendCfg() []byte {
	s3Config := backend.S3Config{
		AccessKeyID:     cfg.AccessKeyID,
		AccessKeySecret: cfg.AccessKeySecret,
		Endpoint:        cfg.Endpoint,
		Scheme:          cfg.Scheme,
		BucketName:      cfg.BucketName,
		Region:          cfg.Region,
		ObjectPrefix:    cfg.BlobPrefix,
	}
	b, _ := json.Marshal(s3Config)
	return b
}

func (cfg *S3BackendConfig) backendType() string {
	return "s3"
}
