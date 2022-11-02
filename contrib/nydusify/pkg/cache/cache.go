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
	"io/ioutil"
	"strconv"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/images"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Opt configures Nydus cache
type Opt struct {
	// Maximum records(bootstrap layer + blob layer) in cache image.
	MaxRecords uint
	// Version of cache image, we need to discard cache layers when
	// the required version (specified by `--build-cache-version`)
	// is unmatched with the cache image version, for example nydus
	// bootstrap format has a minor upgrade.
	Version string
	// Bootstrap's RAFS version of cache image, we need to discard cache
	// layers when the required version (specified by `--fs-version`) is
	// unmatched with the fs version recorded in cache image, for example
	// we can't use rafs v5 cache layers for rafs v6 image.
	FsVersion string
	// Make cache image manifest compatible with the docker v2 media
	// type defined in github.com/containerd/containerd/images.
	DockerV2Format bool
	// The blob layer record will not be written to cache image if
	// the backend be specified, because the blob layer will be uploaded
	// to backend.
	Backend backend.Backend
}

// Cache creates an image to store cache records in its image manifest,
// every record presents the relationship like:
//
// source_layer_chainid -> (nydus_blob_layer_digest, nydus_bootstrap_layer_digest)
// If the converter hits cache record during build source layer, we can
// skip the layer building, see cache image example: examples/manifest/cache_manifest.json.
//
// Here is the build cache workflow:
// 1. Import cache records from registry;
// 2. Check cache record using source layer ChainID before layer build,
// skip layer build if the cache hit;
// 3. Export new cache records to registry;
type Cache struct {
	opt Opt
	// Remote is responsible for pulling & pushing cache image
	remote *remote.Remote
	// Records referenced
	referenceRecords map[digest.Digest]*Record
	// Records pulled from registry
	pulledRecords map[digest.Digest]*Record
	// Records to be push to registry
	pushedRecords []*Record
}

// New creates Nydus cache instance,
func New(remote *remote.Remote, opt Opt) (*Cache, error) {
	cache := &Cache{
		opt:    opt,
		remote: remote,
		// source_layer_chain_id -> cache_record
		pulledRecords:    make(map[digest.Digest]*Record),
		referenceRecords: make(map[digest.Digest]*Record),
		pushedRecords:    []*Record{},
	}

	return cache, nil
}

func (cacheRecord *Record) GetReferenceBlobs() []string {
	listStr := cacheRecord.NydusBootstrapDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs]
	if listStr == "" {
		return []string{}
	}
	var blobs []string
	if err := json.Unmarshal([]byte(listStr), &blobs); err != nil {
		return []string{}
	}
	return blobs
}

func (cache *Cache) GetReference(d digest.Digest) *Record {
	r, ok := cache.referenceRecords[d]
	if !ok {
		return nil
	}
	return r
}

func (cache *Cache) SetReference(layer *ocispec.Descriptor) {
	record := cache.layerToRecord(layer)
	cache.referenceRecords[layer.Digest] = record
}

func (cache *Cache) recordToLayer(record *Record) (*ocispec.Descriptor, *ocispec.Descriptor) {
	// Handle referenced nydus data blob
	if record.SourceChainID == "" {
		if record.NydusBlobDesc != nil {
			if cache.opt.Backend.Type() == backend.RegistryBackend {
				return nil, &ocispec.Descriptor{
					MediaType: utils.MediaTypeNydusBlob,
					Digest:    record.NydusBlobDesc.Digest,
					Size:      record.NydusBlobDesc.Size,
					Annotations: map[string]string{
						utils.LayerAnnotationNydusBlob: "true",
					},
				}
			}
		}
		return nil, nil
	}

	bootstrapCacheMediaType := ocispec.MediaTypeImageLayerGzip
	if cache.opt.DockerV2Format {
		bootstrapCacheMediaType = images.MediaTypeDockerSchema2LayerGzip
	}
	bootstrapCacheDesc := &ocispec.Descriptor{
		MediaType: bootstrapCacheMediaType,
		Digest:    record.NydusBootstrapDesc.Digest,
		Size:      record.NydusBootstrapDesc.Size,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBootstrap:     "true",
			utils.LayerAnnotationNydusFsVersion:     cache.opt.FsVersion,
			utils.LayerAnnotationNydusSourceChainID: record.SourceChainID.String(),
			// Use the annotation to record bootstrap layer DiffID.
			utils.LayerAnnotationUncompressed: record.NydusBootstrapDiffID.String(),
		},
	}
	if referenceBlobsStr, ok := record.NydusBootstrapDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs]; ok {
		bootstrapCacheDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs] = referenceBlobsStr
	}

	var blobCacheDesc *ocispec.Descriptor
	if record.NydusBlobDesc != nil {
		// Record blob layer to cache image if the blob be pushed
		// to registry instead of storage backend.
		if cache.opt.Backend.Type() == backend.RegistryBackend {
			blobCacheDesc = &ocispec.Descriptor{
				MediaType: utils.MediaTypeNydusBlob,
				Digest:    record.NydusBlobDesc.Digest,
				Size:      record.NydusBlobDesc.Size,
				Annotations: map[string]string{
					utils.LayerAnnotationNydusBlob:          "true",
					utils.LayerAnnotationNydusSourceChainID: record.SourceChainID.String(),
				},
			}
		} else {
			bootstrapCacheDesc.Annotations[utils.LayerAnnotationNydusBlobDigest] = record.NydusBlobDesc.Digest.String()
			bootstrapCacheDesc.Annotations[utils.LayerAnnotationNydusBlobSize] = strconv.FormatInt(record.NydusBlobDesc.Size, 10)
		}
	}

	return bootstrapCacheDesc, blobCacheDesc
}

func (cache *Cache) exportRecordsToLayers() []ocispec.Descriptor {
	var (
		layers          []ocispec.Descriptor
		referenceLayers []ocispec.Descriptor
	)

	for _, record := range cache.pushedRecords {
		referenceBlobIDs := record.GetReferenceBlobs()
		for _, blobID := range referenceBlobIDs {
			// for oss backend, GetReference always return nil
			// for registry backend, GetReference should not return nil
			referenceRecord := cache.GetReference(digest.NewDigestFromEncoded(digest.SHA256, blobID))
			if referenceRecord != nil {
				_, blobDesc := cache.recordToLayer(referenceRecord)
				referenceLayers = append(referenceLayers, *blobDesc)
			}
		}
		bootstrapCacheDesc, blobCacheDesc := cache.recordToLayer(record)
		layers = append(layers, *bootstrapCacheDesc)
		if blobCacheDesc != nil {
			layers = append(layers, *blobCacheDesc)
		}
	}

	return append(referenceLayers, layers...)
}

func (cache *Cache) layerToRecord(layer *ocispec.Descriptor) *Record {
	sourceChainIDStr, ok := layer.Annotations[utils.LayerAnnotationNydusSourceChainID]
	if !ok {
		if layer.Annotations[utils.LayerAnnotationNydusBlob] == "true" {
			// for reference blob layers
			return &Record{
				NydusBlobDesc: &ocispec.Descriptor{
					MediaType: layer.MediaType,
					Digest:    layer.Digest,
					Size:      layer.Size,
					Annotations: map[string]string{
						utils.LayerAnnotationNydusBlob: "true",
					},
				},
			}
		}
		return nil
	}
	sourceChainID := digest.Digest(sourceChainIDStr)
	if sourceChainID.Validate() != nil {
		return nil
	}
	if layer.Annotations == nil {
		return nil
	}

	// Handle bootstrap cache layer
	if layer.Annotations[utils.LayerAnnotationNydusBootstrap] == "true" {
		uncompressedDigestStr := layer.Annotations[utils.LayerAnnotationUncompressed]
		if uncompressedDigestStr == "" {
			return nil
		}
		bootstrapDiffID := digest.Digest(uncompressedDigestStr)
		if bootstrapDiffID.Validate() != nil {
			return nil
		}
		bootstrapDesc := ocispec.Descriptor{
			MediaType: layer.MediaType,
			Digest:    layer.Digest,
			Size:      layer.Size,
			Annotations: map[string]string{
				utils.LayerAnnotationNydusBootstrap: "true",
				utils.LayerAnnotationNydusFsVersion: cache.opt.FsVersion,
				utils.LayerAnnotationUncompressed:   uncompressedDigestStr,
			},
		}
		referenceBlobsStr := layer.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs]
		if referenceBlobsStr != "" {
			bootstrapDesc.Annotations[utils.LayerAnnotationNydusReferenceBlobIDs] = referenceBlobsStr
		}
		var nydusBlobDesc *ocispec.Descriptor
		if layer.Annotations[utils.LayerAnnotationNydusBlobDigest] != "" &&
			layer.Annotations[utils.LayerAnnotationNydusBlobSize] != "" {
			blobDigest := digest.Digest(layer.Annotations[utils.LayerAnnotationNydusBlobDigest])
			if blobDigest.Validate() != nil {
				return nil
			}
			blobSize, err := strconv.ParseInt(layer.Annotations[utils.LayerAnnotationNydusBlobSize], 10, 64)
			if err != nil {
				return nil
			}
			nydusBlobDesc = &ocispec.Descriptor{
				MediaType: utils.MediaTypeNydusBlob,
				Digest:    blobDigest,
				Size:      blobSize,
				Annotations: map[string]string{
					utils.LayerAnnotationNydusBlob: "true",
				},
			}
		}
		return &Record{
			SourceChainID:        sourceChainID,
			NydusBootstrapDesc:   &bootstrapDesc,
			NydusBlobDesc:        nydusBlobDesc,
			NydusBootstrapDiffID: bootstrapDiffID,
		}
	}

	// Handle blob cache layer
	if layer.Annotations[utils.LayerAnnotationNydusBlob] == "true" {
		nydusBlobDesc := &ocispec.Descriptor{
			MediaType: layer.MediaType,
			Digest:    layer.Digest,
			Size:      layer.Size,
			Annotations: map[string]string{
				utils.LayerAnnotationNydusBlob: "true",
			},
		}
		return &Record{
			SourceChainID: sourceChainID,
			NydusBlobDesc: nydusBlobDesc,
		}
	}

	return nil
}

func mergeRecord(old, new *Record) *Record {
	if old == nil {
		old = &Record{
			SourceChainID: new.SourceChainID,
		}
	}

	if new.NydusBootstrapDesc != nil {
		old.NydusBootstrapDesc = new.NydusBootstrapDesc
		old.NydusBootstrapDiffID = new.NydusBootstrapDiffID
	}

	if new.NydusBlobDesc != nil {
		old.NydusBlobDesc = new.NydusBlobDesc
	}

	return old
}

func (cache *Cache) importRecordsFromLayers(layers []ocispec.Descriptor) {
	pulledRecords := make(map[digest.Digest]*Record)
	referenceRecords := make(map[digest.Digest]*Record)
	pushedRecords := []*Record{}

	for _, layer := range layers {
		record := cache.layerToRecord(&layer)
		if record != nil {
			if record.SourceChainID == "" {
				referenceRecords[record.NydusBlobDesc.Digest] = record
				logrus.Infof("Found reference blob layer %s", record.NydusBlobDesc.Digest)
			} else {
				// Merge bootstrap and related blob layer to record
				newRecord := mergeRecord(
					pulledRecords[record.SourceChainID],
					record,
				)
				pulledRecords[record.SourceChainID] = newRecord
				pushedRecords = append(pushedRecords, newRecord)
			}
		} else {
			logrus.Warnf("Strange! Build cache layer can't produce a valid record. %s", layer.Digest)
		}
	}

	cache.pulledRecords = pulledRecords
	cache.pushedRecords = pushedRecords
	cache.referenceRecords = referenceRecords
}

// Export pushes cache manifest index to remote registry
func (cache *Cache) Export(ctx context.Context) error {
	if len(cache.pushedRecords) == 0 {
		return nil
	}

	layers := cache.exportRecordsToLayers()

	// Ensure layers from manifest match with image config,
	// this will keep compatibility when using docker pull
	// for the image that only included bootstrap layers.
	diffIDs := []digest.Digest{}
	for _, layer := range layers {
		var diffID digest.Digest
		if layer.MediaType == utils.MediaTypeNydusBlob {
			diffID = layer.Digest
		} else {
			diffID = digest.Digest(layer.Annotations[utils.LayerAnnotationUncompressed])
		}
		if diffID.Validate() == nil {
			diffIDs = append(diffIDs, diffID)
		} else {
			logrus.Warn("Drop the entire diff id list due to an invalid diff id")
			diffIDs = []digest.Digest{}
			// It is possible that some existing cache images don't have diff ids,
			// but we can't break the cache export, so just break the loop.
			break
		}
	}

	// Prepare empty image config, just for registry API compatibility,
	// manifest requires a valid config field.
	configMediaType := ocispec.MediaTypeImageConfig
	if cache.opt.DockerV2Format {
		configMediaType = images.MediaTypeDockerSchema2Config
	}
	config := ocispec.Image{
		Config: ocispec.ImageConfig{},
		RootFS: ocispec.RootFS{
			Type: "layers",
			// Layers from manifest must be match image config.
			DiffIDs: diffIDs,
		},
	}
	configDesc, configBytes, err := utils.MarshalToDesc(config, configMediaType)
	if err != nil {
		return errors.Wrap(err, "Marshal cache config")
	}
	if err := cache.remote.Push(ctx, *configDesc, false, bytes.NewReader(configBytes)); err != nil {
		return errors.Wrap(err, "Push cache config")
	}

	// Push cache manifest to remote registry
	mediaType := ocispec.MediaTypeImageManifest
	if cache.opt.DockerV2Format {
		mediaType = images.MediaTypeDockerSchema2Manifest
	}

	manifest := Manifest{
		MediaType: mediaType,
		Manifest: ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			// Just for registry API compatibility, registry required a
			// valid config field.
			Config: *configDesc,
			Layers: layers,
			Annotations: map[string]string{
				utils.ManifestNydusCache:            cache.opt.Version,
				utils.LayerAnnotationNydusFsVersion: cache.opt.FsVersion,
			},
		},
	}

	manifestDesc, manifestBytes, err := utils.MarshalToDesc(manifest, manifest.MediaType)
	if err != nil {
		return errors.Wrap(err, "Push cache manifest")
	}

	if err := cache.remote.Push(ctx, *manifestDesc, false, bytes.NewReader(manifestBytes)); err != nil {
		return errors.Wrap(err, "Push cache manifest")
	}

	return nil
}

// Import pulls cache manifest index from remote registry
func (cache *Cache) Import(ctx context.Context) error {
	manifestDesc, err := cache.remote.Resolve(ctx)
	if err != nil {
		return errors.Wrap(err, "Resolve cache image")
	}

	// Fetch cache manifest from remote registry
	manifestReader, err := cache.remote.Pull(ctx, *manifestDesc, true)
	if err != nil {
		return errors.Wrap(err, "Pull cache image")
	}
	defer manifestReader.Close()

	manifestBytes, err := ioutil.ReadAll(manifestReader)
	if err != nil {
		return errors.Wrap(err, "Read cache manifest")
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return errors.Wrap(err, "Unmarshal cache manifest")
	}

	// Discard the cache if mismatched version
	if manifest.Annotations[utils.ManifestNydusCache] != cache.opt.Version {
		return fmt.Errorf(
			"unmatched cache image version %s, required to be %s",
			manifest.Annotations[utils.ManifestNydusCache], cache.opt.Version,
		)
	}

	// Discard the cache if mismatched RAFS FsVersion
	// If utils.LayerAnnotationNydusFsVersion == "" and cache.opt.FsVersion == "5",
	// it should be old cache image.
	if manifest.Annotations[utils.LayerAnnotationNydusFsVersion] != cache.opt.FsVersion &&
		!(manifest.Annotations[utils.LayerAnnotationNydusFsVersion] == "" && cache.opt.FsVersion == "5") {
		return fmt.Errorf(
			"unmatched fs version %s, required to be %s",
			manifest.Annotations[utils.LayerAnnotationNydusFsVersion], cache.opt.FsVersion,
		)
	}

	cache.importRecordsFromLayers(manifest.Layers)

	return nil
}

// Check checks bootstrap & blob layer exists in registry or storage backend
func (cache *Cache) Check(ctx context.Context, layerChainID digest.Digest) (*Record, io.ReadCloser, io.ReadCloser, error) {
	record, ok := cache.pulledRecords[layerChainID]
	if !ok {
		return nil, nil, nil, nil
	}

	// Check bootstrap layer on cache
	bootstrapReader, err := cache.remote.Pull(ctx, *record.NydusBootstrapDesc, true)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Check bootstrap layer")
	}
	defer func() {
		if err != nil {
			bootstrapReader.Close()
		}
	}()

	var exist bool
	var blobReader io.ReadCloser

	// Check blob layer on cache
	if record.NydusBlobDesc != nil {
		if cache.opt.Backend.Type() == backend.RegistryBackend {
			blobReader, err = cache.remote.Pull(ctx, *record.NydusBlobDesc, true)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Check blob layer")
			}
		} else {
			exist, err = cache.opt.Backend.Check(record.NydusBlobDesc.Digest.Hex())
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "Check blob on backend")
			} else if !exist {
				err = errors.New("Not found blob on backend")
				return nil, nil, nil, err
			}
		}
	}

	return record, bootstrapReader, blobReader, nil
}

// Record puts new bootstrap & blob layer to cache record, it's a limited queue.
func (cache *Cache) Record(records []*Record) {
	moveFront := map[digest.Digest]bool{}
	for _, record := range records {
		moveFront[record.SourceChainID] = true
	}

	pushedRecords := records
	for _, record := range cache.pushedRecords {
		if !moveFront[record.SourceChainID] {
			pushedRecords = append(pushedRecords, record)
			if len(pushedRecords) >= int(cache.opt.MaxRecords) {
				break
			}
		}
	}

	if len(pushedRecords) > int(cache.opt.MaxRecords) {
		cache.pushedRecords = pushedRecords[:int(cache.opt.MaxRecords)]
	} else {
		cache.pushedRecords = pushedRecords
	}
}

// PullBootstrap pulls bootstrap layer from registry, and unpack to a specified path,
// we can use it to prepare parent bootstrap for building.
func (cache *Cache) PullBootstrap(ctx context.Context, bootstrapDesc *ocispec.Descriptor, target string) error {
	reader, err := cache.remote.Pull(ctx, *bootstrapDesc, true)
	if err != nil {
		return errors.Wrap(err, "Pull cached bootstrap layer")
	}
	defer reader.Close()

	if err := utils.UnpackFile(reader, utils.BootstrapFileNameInLayer, target); err != nil {
		return errors.Wrap(err, "Unpack cached bootstrap layer")
	}

	return nil
}

// Push pushes cache image to registry
func (cache *Cache) Push(ctx context.Context, desc ocispec.Descriptor, reader io.Reader) error {
	return cache.remote.Push(ctx, desc, true, reader)
}
