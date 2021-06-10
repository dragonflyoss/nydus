// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

func makeRecord(id int64, hashBlob bool) *CacheRecord {
	var blobDesc *ocispec.Descriptor
	idStr := strconv.FormatInt(id, 10)
	if hashBlob {
		blobDesc = &ocispec.Descriptor{
			MediaType: utils.MediaTypeNydusBlob,
			Digest:    digest.FromString("blob-" + idStr),
			Size:      id,
		}
	}
	return &CacheRecord{
		SourceChainID: digest.FromString("chain-" + idStr),
		NydusBootstrapDesc: &ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageLayerGzip,
			Digest:    digest.FromString("bootstrap-" + idStr),
			Size:      id,
		},
		NydusBootstrapDiffID: digest.FromString("bootstrap-uncompressed-" + idStr),
		NydusBlobDesc:        blobDesc,
	}
}

func makeBootstrapLayer(id int64, hasBlob bool) ocispec.Descriptor {
	idStr := strconv.FormatInt(id, 10)
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("bootstrap-" + idStr),
		Size:      id,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBootstrap:     "true",
			utils.LayerAnnotationNydusSourceChainID: digest.FromString("chain-" + idStr).String(),
			utils.LayerAnnotationUncompressed:       digest.FromString("bootstrap-uncompressed-" + idStr).String(),
		},
	}
	if hasBlob {
		desc.Annotations[utils.LayerAnnotationNydusBlobDigest] = digest.FromString("blob-" + idStr).String()
		desc.Annotations[utils.LayerAnnotationNydusBlobSize] = fmt.Sprintf("%d", id)
	}
	return desc
}

func makeBlobLayer(id int64) ocispec.Descriptor {
	idStr := strconv.FormatInt(id, 10)
	return ocispec.Descriptor{
		MediaType: utils.MediaTypeNydusBlob,
		Digest:    digest.FromString("blob-" + idStr),
		Size:      id,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBlob:          "true",
			utils.LayerAnnotationNydusSourceChainID: digest.FromString("chain-" + idStr).String(),
		},
	}
}

func testWithBackend(t *testing.T, _backend backend.Backend) {
	cache, err := New(nil, Opt{
		MaxRecords:     3,
		DockerV2Format: false,
		Backend:        _backend,
	})
	assert.Nil(t, err)

	exported := []*CacheRecord{
		makeRecord(1, true),
		makeRecord(2, true),
		makeRecord(3, false),
	}
	cache.Record(exported)
	cache.Record(exported)
	layers := cache.exportRecordsToLayers()

	if _backend.Type() == backend.RegistryBackend {
		assert.Equal(t, layers, []ocispec.Descriptor{
			makeBootstrapLayer(1, false),
			makeBlobLayer(1),
			makeBootstrapLayer(2, false),
			makeBlobLayer(2),
			makeBootstrapLayer(3, false),
		})
	} else {
		assert.Equal(t, layers, []ocispec.Descriptor{
			makeBootstrapLayer(1, true),
			makeBootstrapLayer(2, true),
			makeBootstrapLayer(3, false),
		})
	}

	cache.importRecordsFromLayers(layers)
	cache.Record([]*CacheRecord{
		makeRecord(4, true),
		makeRecord(5, true),
	})
	layers = cache.exportRecordsToLayers()

	if _backend.Type() == backend.RegistryBackend {
		assert.Equal(t, layers, []ocispec.Descriptor{
			makeBootstrapLayer(4, false),
			makeBlobLayer(4),
			makeBootstrapLayer(5, false),
			makeBlobLayer(5),
			makeBootstrapLayer(1, false),
			makeBlobLayer(1),
		})
	} else {
		assert.Equal(t, layers, []ocispec.Descriptor{
			makeBootstrapLayer(4, true),
			makeBootstrapLayer(5, true),
			makeBootstrapLayer(1, true),
		})
	}
}

func TestCache(t *testing.T) {
	testWithBackend(t, &backend.Registry{})
	testWithBackend(t, &backend.OSSBackend{})
}
