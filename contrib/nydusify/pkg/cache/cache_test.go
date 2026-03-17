// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
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

func TestGetAndSetReference(t *testing.T) {
	cache, err := New(nil, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	assert.NoError(t, err)

	refDigest := digest.FromString("ref-only")
	assert.Nil(t, cache.GetReference(refDigest))

	layer := &ocispec.Descriptor{
		MediaType: utils.MediaTypeNydusBlob,
		Digest:    refDigest,
		Size:      128,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBlob: "true",
		},
	}
	cache.SetReference(layer)

	record := cache.GetReference(refDigest)
	assert.NotNil(t, record)
	assert.Equal(t, refDigest, record.NydusBlobDesc.Digest)
	assert.Nil(t, record.NydusBootstrapDesc)
}

func TestMergeRecord(t *testing.T) {
	bootstrapOnly := &Record{
		SourceChainID:        digest.FromString("chain-bootstrap"),
		NydusBootstrapDesc:   &ocispec.Descriptor{Digest: digest.FromString("bootstrap")},
		NydusBootstrapDiffID: digest.FromString("bootstrap-diff"),
	}
	merged := mergeRecord(nil, bootstrapOnly)
	assert.Equal(t, bootstrapOnly.SourceChainID, merged.SourceChainID)
	assert.Equal(t, bootstrapOnly.NydusBootstrapDesc.Digest, merged.NydusBootstrapDesc.Digest)
	assert.Nil(t, merged.NydusBlobDesc)

	blobOnly := &Record{
		SourceChainID: digest.FromString("chain-bootstrap"),
		NydusBlobDesc: &ocispec.Descriptor{Digest: digest.FromString("blob")},
	}
	merged = mergeRecord(merged, blobOnly)
	assert.Equal(t, digest.FromString("blob"), merged.NydusBlobDesc.Digest)
	assert.Equal(t, digest.FromString("bootstrap-diff"), merged.NydusBootstrapDiffID)
}

func TestRecordQueueBehavior(t *testing.T) {
	cache, err := New(nil, Opt{Backend: &backend.Registry{}, FsVersion: "6", MaxRecords: 3})
	assert.NoError(t, err)

	cache.pushedRecords = []*Record{makeRecord(1, true), makeRecord(2, true), makeRecord(3, true)}
	cache.Record([]*Record{makeRecord(2, true), makeRecord(4, true)})
	assert.Equal(t, []digest.Digest{
		digest.FromString("chain-2"),
		digest.FromString("chain-4"),
		digest.FromString("chain-1"),
	}, []digest.Digest{
		cache.pushedRecords[0].SourceChainID,
		cache.pushedRecords[1].SourceChainID,
		cache.pushedRecords[2].SourceChainID,
	})

	cache.Record([]*Record{makeRecord(5, true), makeRecord(6, true), makeRecord(7, true), makeRecord(8, true)})
	assert.Len(t, cache.pushedRecords, 3)
	assert.Equal(t, digest.FromString("chain-5"), cache.pushedRecords[0].SourceChainID)
	assert.Equal(t, digest.FromString("chain-6"), cache.pushedRecords[1].SourceChainID)
	assert.Equal(t, digest.FromString("chain-7"), cache.pushedRecords[2].SourceChainID)
}

func TestExportEmpty(t *testing.T) {
	r, err := remote.New("docker.io/cache:v1", func(bool) remotes.Resolver { return nil })
	require.NoError(t, err)
	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6", Version: "1.0"})
	require.NoError(t, err)

	// Empty pushed records → should return nil immediately
	err = cache.Export(context.Background())
	require.NoError(t, err)
}

type mockWriter struct {
	bytes.Buffer
}

func (w *mockWriter) Close() error          { return nil }
func (w *mockWriter) Digest() digest.Digest { return digest.FromBytes(w.Bytes()) }
func (w *mockWriter) Commit(_ context.Context, _ int64, _ digest.Digest, _ ...content.Opt) error {
	return nil
}
func (w *mockWriter) Status() (content.Status, error) { return content.Status{}, nil }
func (w *mockWriter) Truncate(_ int64) error          { return nil }

type mockPusher struct {
	pushErr error
}

func (p *mockPusher) Push(_ context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	if p.pushErr != nil {
		return nil, p.pushErr
	}
	return &mockWriter{}, nil
}

type mockFetcher struct {
	fetchData []byte
	fetchErr  error
}

func (f *mockFetcher) Fetch(_ context.Context, _ ocispec.Descriptor) (io.ReadCloser, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return io.NopCloser(bytes.NewReader(f.fetchData)), nil
}

type mockResolver struct {
	resolveDesc ocispec.Descriptor
	resolveErr  error
	pusher      *mockPusher
	fetcher     *mockFetcher
}

func (r *mockResolver) Resolve(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
	return "", r.resolveDesc, r.resolveErr
}

func (r *mockResolver) Fetcher(_ context.Context, _ string) (remotes.Fetcher, error) {
	return r.fetcher, nil
}

func (r *mockResolver) Pusher(_ context.Context, _ string) (remotes.Pusher, error) {
	return r.pusher, nil
}

func (r *mockResolver) PusherInChunked(_ context.Context, _ string) (remotes.PusherInChunked, error) {
	return nil, errors.New("not implemented")
}

func newMockRemote(t *testing.T, resolver *mockResolver) *remote.Remote {
	t.Helper()
	r, err := remote.New("docker.io/cache:v1", func(bool) remotes.Resolver {
		return resolver
	})
	require.NoError(t, err)
	return r
}

func TestExportSuccess(t *testing.T) {
	resolver := &mockResolver{
		pusher: &mockPusher{},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{
		Backend:    &backend.Registry{},
		FsVersion:  "6",
		Version:    "1.0",
		MaxRecords: 5,
	})
	require.NoError(t, err)

	cache.Record([]*Record{makeRecord(1, true)})
	err = cache.Export(context.Background())
	require.NoError(t, err)
}

func TestExportPushError(t *testing.T) {
	resolver := &mockResolver{
		pusher: &mockPusher{pushErr: errors.New("push failed")},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{
		Backend:    &backend.Registry{},
		FsVersion:  "6",
		Version:    "1.0",
		MaxRecords: 5,
	})
	require.NoError(t, err)

	cache.Record([]*Record{makeRecord(1, true)})
	err = cache.Export(context.Background())
	require.Error(t, err)
}

func TestExportAlreadyExists(t *testing.T) {
	resolver := &mockResolver{
		pusher: &mockPusher{pushErr: errdefs.ErrAlreadyExists},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{
		Backend:    &backend.Registry{},
		FsVersion:  "6",
		Version:    "1.0",
		MaxRecords: 5,
	})
	require.NoError(t, err)

	cache.Record([]*Record{makeRecord(1, false)})
	err = cache.Export(context.Background())
	// AlreadyExists is handled gracefully by remote.Push
	require.NoError(t, err)
}

func TestImportResolveError(t *testing.T) {
	resolver := &mockResolver{
		resolveErr: errors.New("not found"),
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6", Version: "1.0"})
	require.NoError(t, err)

	err = cache.Import(context.Background())
	require.ErrorContains(t, err, "Resolve cache image")
}

func TestImportPullError(t *testing.T) {
	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchErr: errors.New("network error")},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6", Version: "1.0"})
	require.NoError(t, err)

	err = cache.Import(context.Background())
	require.ErrorContains(t, err, "Pull cache image")
}

func TestImportVersionMismatch(t *testing.T) {
	manifest := Manifest{}
	manifest.Annotations = map[string]string{
		utils.ManifestNydusCache:            "2.0",
		utils.LayerAnnotationNydusFsVersion: "6",
	}
	manifestBytes, _ := json.Marshal(manifest)

	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchData: manifestBytes},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6", Version: "1.0"})
	require.NoError(t, err)

	err = cache.Import(context.Background())
	require.ErrorContains(t, err, "unmatched cache image version")
}

func TestImportFsVersionMismatch(t *testing.T) {
	manifest := Manifest{}
	manifest.Annotations = map[string]string{
		utils.ManifestNydusCache:            "1.0",
		utils.LayerAnnotationNydusFsVersion: "5",
	}
	manifestBytes, _ := json.Marshal(manifest)

	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchData: manifestBytes},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6", Version: "1.0"})
	require.NoError(t, err)

	err = cache.Import(context.Background())
	require.ErrorContains(t, err, "unmatched fs version")
}

func TestImportSuccess(t *testing.T) {
	layers := []ocispec.Descriptor{makeBootstrapLayer(1, true)}
	manifest := Manifest{}
	manifest.Layers = layers
	manifest.Annotations = map[string]string{
		utils.ManifestNydusCache:            "1.0",
		utils.LayerAnnotationNydusFsVersion: "6",
	}
	manifestBytes, _ := json.Marshal(manifest)

	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchData: manifestBytes},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.OSSBackend{}, FsVersion: "6", Version: "1.0"})
	require.NoError(t, err)

	err = cache.Import(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, cache.pulledRecords)
}

func TestCheckNotFound(t *testing.T) {
	r := newMockRemote(t, &mockResolver{})
	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	require.NoError(t, err)

	record, br, blob, err := cache.Check(context.Background(), digest.FromString("missing"))
	require.NoError(t, err)
	require.Nil(t, record)
	require.Nil(t, br)
	require.Nil(t, blob)
}

func TestCheckBootstrapPullError(t *testing.T) {
	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchErr: errors.New("pull failed")},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	require.NoError(t, err)

	chainID := digest.FromString("chain-1")
	cache.pulledRecords[chainID] = makeRecord(1, true)

	_, _, _, err = cache.Check(context.Background(), chainID)
	require.ErrorContains(t, err, "Check bootstrap layer")
}

func TestPush(t *testing.T) {
	resolver := &mockResolver{
		pusher: &mockPusher{},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	require.NoError(t, err)

	desc := ocispec.Descriptor{Digest: digest.FromString("test"), Size: 4}
	err = cache.Push(context.Background(), desc, bytes.NewReader([]byte("test")))
	require.NoError(t, err)
}

func TestPullBootstrapError(t *testing.T) {
	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchErr: errors.New("pull failed")},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	require.NoError(t, err)

	err = cache.PullBootstrap(context.Background(), &ocispec.Descriptor{}, "/tmp/target")
	require.ErrorContains(t, err, "Pull cached bootstrap layer")
}

func TestCheckSuccessRegistryBackendWithBlob(t *testing.T) {
	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchData: []byte("bootstrap-data")},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	require.NoError(t, err)

	chainID := digest.FromString("chain-1")
	cache.pulledRecords[chainID] = makeRecord(1, true)

	record, bootstrapReader, blobReader, err := cache.Check(context.Background(), chainID)
	require.NoError(t, err)
	require.NotNil(t, record)
	require.NotNil(t, bootstrapReader)
	require.NotNil(t, blobReader)
	bootstrapReader.Close()
	blobReader.Close()
}

func TestCheckSuccessRegistryNoBlobDesc(t *testing.T) {
	resolver := &mockResolver{
		fetcher: &mockFetcher{fetchData: []byte("bootstrap-data")},
	}
	r := newMockRemote(t, resolver)

	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6"})
	require.NoError(t, err)

	chainID := digest.FromString("chain-no-blob")
	cache.pulledRecords[chainID] = makeRecord(3, false)

	record, bootstrapReader, blobReader, err := cache.Check(context.Background(), chainID)
	require.NoError(t, err)
	require.NotNil(t, record)
	require.NotNil(t, bootstrapReader)
	require.Nil(t, blobReader)
	bootstrapReader.Close()
}

func TestRecordMaxRecords(t *testing.T) {
	r := newMockRemote(t, &mockResolver{})
	cache, err := New(r, Opt{Backend: &backend.Registry{}, FsVersion: "6", MaxRecords: 2})
	require.NoError(t, err)

	records := []*Record{makeRecord(1, true), makeRecord(2, true), makeRecord(3, true)}
	cache.Record(records)
	require.Len(t, cache.pushedRecords, 2)
}
