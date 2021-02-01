package cache

import (
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type CacheManifest struct {
	MediaType string `json:"mediaType,omitempty"`
	ocispec.Manifest
}

type CacheRecord struct {
	NydusBlobDesc        *ocispec.Descriptor
	NydusBootstrapDesc   *ocispec.Descriptor
	NydusBootstrapDiffID digest.Digest
}

type CacheRecordWithChainID struct {
	SourceChainID digest.Digest
	CacheRecord
}
