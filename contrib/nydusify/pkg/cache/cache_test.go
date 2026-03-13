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

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func TestGetReferenceBlobs(t *testing.T) {
	record := &Record{
		NydusBootstrapDesc: &ocispec.Descriptor{
			Annotations: map[string]string{
				utils.LayerAnnotationNydusReferenceBlobIDs: `["blob1","blob2"]`,
			},
		},
	}
	assert.Equal(t, []string{"blob1", "blob2"}, record.GetReferenceBlobs())

	record.NydusBootstrapDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs] = `not-json`
	assert.Empty(t, record.GetReferenceBlobs())

	record.NydusBootstrapDesc.Annotations = map[string]string{}
	assert.Empty(t, record.GetReferenceBlobs())
}

func makeRecord(id int64, hashBlob bool) *Record {
	var blobDesc *ocispec.Descriptor
	idStr := strconv.FormatInt(id, 10)
	if hashBlob {
		blobDesc = &ocispec.Descriptor{
			MediaType: utils.MediaTypeNydusBlob,
			Digest:    digest.FromString("blob-" + idStr),
			Size:      id,
		}
	}
	return &Record{
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
			utils.LayerAnnotationNydusFsVersion:     "6",
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
		FsVersion:      "6",
	})
	assert.Nil(t, err)

	exported := []*Record{
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
	cache.Record([]*Record{
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

func TestLayerToRecord(t *testing.T) {
	cache, err := New(nil, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	assert.NoError(t, err)

	assert.Nil(t, cache.layerToRecord(&ocispec.Descriptor{}))

	referenceLayer := &ocispec.Descriptor{
		MediaType: utils.MediaTypeNydusBlob,
		Digest:    digest.FromString("reference-blob"),
		Size:      128,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBlob: "true",
		},
	}
	referenceRecord := cache.layerToRecord(referenceLayer)
	assert.NotNil(t, referenceRecord)
	assert.Nil(t, referenceRecord.NydusBootstrapDesc)
	assert.Equal(t, referenceLayer.Digest, referenceRecord.NydusBlobDesc.Digest)

	invalidChainLayer := makeBootstrapLayer(1, false)
	invalidChainLayer.Annotations[utils.LayerAnnotationNydusSourceChainID] = "bad-digest"
	assert.Nil(t, cache.layerToRecord(&invalidChainLayer))

	missingDiffIDLayer := makeBootstrapLayer(2, false)
	delete(missingDiffIDLayer.Annotations, utils.LayerAnnotationUncompressed)
	assert.Nil(t, cache.layerToRecord(&missingDiffIDLayer))

	invalidBlobDigestLayer := makeBootstrapLayer(3, true)
	invalidBlobDigestLayer.Annotations[utils.LayerAnnotationNydusBlobDigest] = "bad-digest"
	assert.Nil(t, cache.layerToRecord(&invalidBlobDigestLayer))

	invalidBlobSizeLayer := makeBootstrapLayer(4, true)
	invalidBlobSizeLayer.Annotations[utils.LayerAnnotationNydusBlobSize] = "invalid"
	assert.Nil(t, cache.layerToRecord(&invalidBlobSizeLayer))

	blobLayer := makeBlobLayer(5)
	record := cache.layerToRecord(&blobLayer)
	assert.NotNil(t, record)
	assert.Equal(t, digest.FromString("chain-5"), record.SourceChainID)
	assert.Equal(t, blobLayer.Digest, record.NydusBlobDesc.Digest)
	assert.Nil(t, record.NydusBootstrapDesc)
}

func TestRecordToLayer(t *testing.T) {
	record := makeRecord(9, true)
	record.NydusBootstrapDesc.Annotations = map[string]string{
		utils.LayerAnnotationNydusReferenceBlobIDs: `["ref-1"]`,
	}

	registryCache, err := New(nil, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	assert.NoError(t, err)
	bootstrapDesc, blobDesc := registryCache.recordToLayer(record)
	assert.NotNil(t, bootstrapDesc)
	assert.NotNil(t, blobDesc)
	assert.Equal(t, record.SourceChainID.String(), bootstrapDesc.Annotations[utils.LayerAnnotationNydusSourceChainID])
	assert.Equal(t, `["ref-1"]`, bootstrapDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs])
	assert.Equal(t, record.NydusBlobDesc.Digest, blobDesc.Digest)

	ossCache, err := New(nil, Opt{Backend: &backend.OSSBackend{}, FsVersion: "6", DockerV2Format: true})
	assert.NoError(t, err)
	bootstrapDesc, blobDesc = ossCache.recordToLayer(record)
	assert.NotNil(t, bootstrapDesc)
	assert.Nil(t, blobDesc)
	assert.Equal(t, record.NydusBlobDesc.Digest.String(), bootstrapDesc.Annotations[utils.LayerAnnotationNydusBlobDigest])
	assert.Equal(t, fmt.Sprintf("%d", record.NydusBlobDesc.Size), bootstrapDesc.Annotations[utils.LayerAnnotationNydusBlobSize])

	referenceRecord := &Record{
		NydusBlobDesc: &ocispec.Descriptor{Digest: digest.FromString("ref-only"), Size: 10},
	}
	bootstrapDesc, blobDesc = registryCache.recordToLayer(referenceRecord)
	assert.Nil(t, bootstrapDesc)
	assert.NotNil(t, blobDesc)
	assert.Equal(t, utils.MediaTypeNydusBlob, blobDesc.MediaType)

	bootstrapDesc, blobDesc = ossCache.recordToLayer(referenceRecord)
	assert.Nil(t, bootstrapDesc)
	assert.Nil(t, blobDesc)
}
