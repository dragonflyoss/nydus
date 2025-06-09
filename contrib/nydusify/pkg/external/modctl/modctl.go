// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package modctl

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/pkg/errors"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	BlobPath     = "/content.v1/docker/registry/v2/blobs/%s/%s/%s/data"
	ReposPath    = "/content.v1/docker/registry/v2/repositories"
	ManifestPath = "/_manifests/tags/%s/current/link"
)

const (
	DefaultFileChunkSize = "4MiB"
)

var mediaTypeChunkSizeMap = map[string]string{
	modelspec.MediaTypeModelWeight:     "64MiB",
	modelspec.MediaTypeModelWeightRaw:  "64MiB",
	modelspec.MediaTypeModelDataset:    "64MiB",
	modelspec.MediaTypeModelDatasetRaw: "64MiB",
}

var _ backend.Handler = &Handler{}

type Handler struct {
	root         string
	registryHost string
	namespace    string
	imageName    string
	tag          string
	manifest     ocispec.Manifest
	blobs        []backend.Blob
	// key is the blob's sha256, value is the blob's mediaType type and index
	blobsMap map[string]blobInfo
	// config layer in modctl's manifest
	blobConfig ocispec.Descriptor
	objectID   uint32
}

type blobInfo struct {
	mediaType string
	// Index in the blobs array
	blobIndex  uint32
	blobDigest string
	blobSize   string
}

type chunk struct {
	blobDigest    string
	blobSize      string
	objectID      uint32
	objectContent Object
	objectOffset  uint64
}

// ObjectID returns the blob index of the chunk
func (c *chunk) ObjectID() uint32 {
	return c.objectID
}

func (c *chunk) ObjectContent() interface{} {
	return c.objectContent
}

// ObjectOffset returns the offset of the chunk in the blob file
func (c *chunk) ObjectOffset() uint64 {
	return c.objectOffset
}

func (c *chunk) FilePath() string {
	return c.objectContent.Path
}

func (c *chunk) LimitChunkSize() string {
	return c.objectContent.ChunkSize
}

func (c *chunk) BlobDigest() string {
	return c.blobDigest
}

func (c *chunk) BlobSize() string {
	return c.blobSize
}

type Object struct {
	Path      string
	ChunkSize string
}

type fileInfo struct {
	name   string
	mode   uint32
	size   uint64
	offset uint64
}

type Option struct {
	Root            string `json:"root"`
	RegistryHost    string `json:"registry_host"`
	Namespace       string `json:"namespace"`
	ImageName       string `json:"image_name"`
	Tag             string `json:"tag"`
	WeightChunkSize uint64 `josn:"weightChunkSize"`
}

func setWeightChunkSize(chunkSize uint64) {
	if chunkSize == 0 {
		chunkSize = 64 * 1024 * 1024
	}
	chunkSizeStr := humanize.IBytes(chunkSize)
	// remove space in chunkSizeStr `16 Mib` -> `16Mib`
	chunkSizeStr = strings.ReplaceAll(chunkSizeStr, " ", "")
	mediaTypeChunkSizeMap[modelspec.MediaTypeModelWeight] = chunkSizeStr
	mediaTypeChunkSizeMap[modelspec.MediaTypeModelWeightRaw] = chunkSizeStr
	mediaTypeChunkSizeMap[modelspec.MediaTypeModelDataset] = chunkSizeStr
	mediaTypeChunkSizeMap[modelspec.MediaTypeModelDatasetRaw] = chunkSizeStr
}

func getChunkSizeByMediaType(mediaType string) string {
	if chunkSize, ok := mediaTypeChunkSizeMap[mediaType]; ok {
		return chunkSize
	}
	return DefaultFileChunkSize
}

func NewHandler(opt Option) (*Handler, error) {
	handler := &Handler{
		root:         opt.Root,
		registryHost: opt.RegistryHost,
		namespace:    opt.Namespace,
		imageName:    opt.ImageName,
		tag:          opt.Tag,
		objectID:     0,
		blobsMap:     make(map[string]blobInfo),
	}
	if opt.WeightChunkSize != 0 {
		setWeightChunkSize(opt.WeightChunkSize)
	}
	if err := initHandler(handler); err != nil {
		return nil, errors.Wrap(err, "init handler")
	}
	return handler, nil
}
func initHandler(handler *Handler) error {
	m, err := handler.extractManifest()
	if err != nil {
		return errors.Wrap(err, "extract manifest failed")
	}
	handler.manifest = *m
	handler.blobs = convertToBlobs(&handler.manifest)
	handler.setBlobConfig(m)
	handler.setBlobsMap()
	return nil
}

func GetOption(srcRef, modCtlRoot string, weightChunkSize uint64) (*Option, error) {
	parts := strings.Split(srcRef, "/")
	if len(parts) != 3 {
		return nil, errors.Errorf("invalid source ref:%s", srcRef)
	}
	nameTagParts := strings.Split(parts[2], ":")
	if len(nameTagParts) != 2 {
		return nil, errors.New("invalid source ref for name and tag")
	}
	opt := Option{
		Root:            modCtlRoot,
		RegistryHost:    parts[0],
		Namespace:       parts[1],
		ImageName:       nameTagParts[0],
		Tag:             nameTagParts[1],
		WeightChunkSize: weightChunkSize,
	}
	return &opt, nil
}

func (handler *Handler) Handle(_ context.Context, file backend.File) ([]backend.Chunk, error) {
	chunks := []backend.Chunk{}
	needIgnore, blobInfo := handler.needIgnore(file.RelativePath)
	if needIgnore {
		return nil, nil
	}
	chunkSize := getChunkSizeByMediaType(blobInfo.mediaType)

	// read the tar file and get the meta of files
	f, err := os.Open(filepath.Join(handler.root, file.RelativePath))
	if err != nil {
		return nil, errors.Wrap(err, "open tar file failed")
	}
	defer f.Close()

	isTar, err := validateTarFile(f)
	if err != nil {
		return nil, errors.Wrap(err, "validate tar file failed")
	}

	var files []fileInfo
	if isTar {
		fs, err := readTarBlob(f)
		if err != nil {
			return nil, errors.Wrap(err, "read blob failed")
		}
		files = fs
	} else {
		fm, err := f.Stat()
		if err != nil {
			return nil, errors.Wrap(err, "stat file failed")
		}
		files = append(files, fileInfo{
			fm.Name(),
			uint32(fm.Mode()),
			uint64(fm.Size()),
			0,
		})
	}

	chunkSizeInInt, err := humanize.ParseBytes(chunkSize)
	if err != nil {
		return nil, errors.Wrap(err, "parse chunk size failed")
	}
	for _, f := range files {
		objectOffsets := backend.SplitObjectOffsets(int64(f.size), int64(chunkSizeInInt))
		for _, objectOffset := range objectOffsets {
			chunks = append(chunks, &chunk{
				blobDigest: blobInfo.blobDigest,
				blobSize:   blobInfo.blobSize,
				objectID:   blobInfo.blobIndex,
				objectContent: Object{
					Path:      f.name,
					ChunkSize: chunkSize,
				},
				objectOffset: f.offset + objectOffset,
			})
		}
	}

	handler.objectID++

	return chunks, nil
}

func (handler *Handler) Backend(context.Context) (*backend.Backend, error) {
	bkd := backend.Backend{
		Version: "v1",
	}
	bkd.Backends = []backend.Config{
		{
			Type: "registry",
		},
	}
	bkd.Blobs = handler.blobs
	return &bkd, nil
}

func (handler *Handler) GetConfig() ([]byte, error) {
	return handler.extractBlobs(handler.blobConfig.Digest.String())
}

func (handler *Handler) GetLayers() []ocispec.Descriptor {
	return handler.manifest.Layers
}

func (handler *Handler) setBlobConfig(m *ocispec.Manifest) {
	handler.blobConfig = m.Config
}

func (handler *Handler) setBlobsMap() {
	for i, blob := range handler.blobs {
		handler.blobsMap[blob.Config.Digest] = blobInfo{
			mediaType:  blob.Config.MediaType,
			blobIndex:  uint32(i),
			blobDigest: blob.Config.Digest,
			blobSize:   blob.Config.Size,
		}
	}
}

func (handler *Handler) extractManifest() (*ocispec.Manifest, error) {
	tagPath := fmt.Sprintf(ManifestPath, handler.tag)
	manifestPath := filepath.Join(handler.root, ReposPath, handler.registryHost, handler.namespace, handler.imageName, tagPath)
	line, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, errors.Wrap(err, "read manifest digest file failed")
	}
	content, err := handler.extractBlobs(string(line))
	if err != nil {
		return nil, errors.Wrap(err, "extract blobs failed")
	}

	var m ocispec.Manifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, errors.Wrap(err, "unmarshal manifest blobs file failed")
	}
	return &m, nil
}

func (handler *Handler) extractBlobs(digest string) ([]byte, error) {
	line := strings.TrimSpace(digest)
	digestSplit := strings.Split(line, ":")
	if len(digestSplit) != 2 {
		return nil, errors.New("invalid digest string")
	}

	blobPath := fmt.Sprintf(BlobPath, digestSplit[0], digestSplit[1][:2], digestSplit[1])
	blobPath = filepath.Join(handler.root, blobPath)
	content, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "read  blobs file failed")
	}
	return content, nil
}

func convertToBlobs(m *ocispec.Manifest) []backend.Blob {
	createBlob := func(layer ocispec.Descriptor) backend.Blob {
		digestStr := layer.Digest.String()
		digestParts := strings.Split(digestStr, ":")
		if len(digestParts) == 2 {
			digestStr = digestParts[1]
		}

		chunkSize := getChunkSizeByMediaType(layer.MediaType)
		return backend.Blob{
			Backend: 0,
			Config: backend.BlobConfig{
				MediaType: layer.MediaType,
				Digest:    digestStr,
				Size:      fmt.Sprintf("%d", layer.Size),
				ChunkSize: chunkSize,
			},
		}
	}

	blobs := make([]backend.Blob, len(m.Layers))

	for i, layer := range m.Layers {
		blobs[i] = createBlob(layer)
	}

	return blobs
}

func (handler *Handler) needIgnore(relPath string) (bool, *blobInfo) {
	// ignore manifest link file
	if strings.HasSuffix(relPath, "link") {
		return true, nil
	}

	// ignore blobs file belong to other image
	parts := strings.Split(relPath, "/")
	if len(parts) < 3 {
		return true, nil
	}

	digest := parts[len(parts)-2]
	blobInfo, ok := handler.blobsMap[digest]
	if !ok {
		return true, nil
	}

	return false, &blobInfo
}

func readTarBlob(r io.ReadSeeker) ([]fileInfo, error) {
	var files []fileInfo
	tarReader := tar.NewReader(r)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, errors.Wrap(err, "read tar file failed")
		}
		currentOffset, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, errors.Wrap(err, "seek tar file failed")
		}
		files = append(files, fileInfo{
			name:   header.Name,
			mode:   uint32(header.Mode),
			size:   uint64(header.Size),
			offset: uint64(currentOffset),
		})
	}
	return files, nil
}

func readRawBlob(layer ocispec.Descriptor) ([]fileInfo, error) {
	if !strings.HasSuffix(layer.MediaType, "raw") {
		return nil, fmt.Errorf("invalid media type: %s", layer.MediaType)
	}

	path, ok := layer.Annotations[filePathKey]
	if !ok || len(path) == 0 {
		return nil, fmt.Errorf("invalid file path")
	}

	b, ok := layer.Annotations[modelspec.AnnotationFileMetadata]
	if !ok || len(b) == 0 {
		return nil, errors.Errorf("missing file metadata annotation")
	}

	var fm modelspec.FileMetadata
	if err := json.Unmarshal([]byte(b), &fm); err != nil {
		return nil, errors.Wrap(err, "unmarshal file metadata failed")
	}
	file := fileInfo{
		name:   path,
		mode:   fm.Mode,
		size:   uint64(fm.Size),
		offset: 0,
	}
	return []fileInfo{file}, nil
}

func validateTarFile(f *os.File) (bool, error) {
	tr := tar.NewReader(f)
	_, err := tr.Next()
	if err != nil && err != io.EOF {
		return false, nil
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, errors.Wrap(err, "reset file pointer failed")
	}
	return true, nil
}
