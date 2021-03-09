// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"strconv"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

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

func makeBootstrapLayer(id int64) ocispec.Descriptor {
	idStr := strconv.FormatInt(id, 10)
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("bootstrap-" + idStr),
		Size:      id,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBootstrap:     "true",
			utils.LayerAnnotationNydusSourceChainID: digest.FromString("chain-" + idStr).String(),
			utils.LayerAnnotationUncompressed:       digest.FromString("bootstrap-uncompressed-" + idStr).String(),
		},
	}
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

func TestCache(t *testing.T) {
	cache, err := New(nil, Opt{
		MaxRecords:     3,
		DockerV2Format: false,
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

	assert.Equal(t, layers, []ocispec.Descriptor{
		makeBootstrapLayer(1),
		makeBlobLayer(1),
		makeBootstrapLayer(2),
		makeBlobLayer(2),
		makeBootstrapLayer(3),
	})

	cache.importLayersToRecords(layers)
	cache.Record([]*CacheRecord{
		makeRecord(4, true),
		makeRecord(5, true),
	})
	layers = cache.exportRecordsToLayers()

	assert.Equal(t, layers, []ocispec.Descriptor{
		makeBootstrapLayer(4),
		makeBlobLayer(4),
		makeBootstrapLayer(5),
		makeBlobLayer(5),
		makeBootstrapLayer(1),
		makeBlobLayer(1),
	})
}
