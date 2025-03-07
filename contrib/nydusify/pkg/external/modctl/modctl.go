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

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
)

const BLOB_PATH = "/content.v1/docker/registry/v2/blobs/%s/%s/%s/data"
const REPOS_PATH = "/content.v1/docker/registry/v2/repositories"
const MANIFEST_PATH = "/_manifests/tags/%s/current/link"

const (
	DefaultFileChunkSize = "4MiB"
)

var mediaTypeChunkSizeMap = map[string]string{
	"application/vnd.cnai.model.weight.v1.tar":  "64MiB",
	"application/vnd.cnai.model.dataset.v1.tar": "64MiB",
}

var _ backend.Handler = &Handler{}

type Handler struct {
	root         string
	registryHost string
	namespace    string
	imageName    string
	tag          string
	manifest     Manifest
	blobs        []backend.Blob
	// key is the blob's sha256, value is the blob's mediaType type and index
	blobsMap map[string]blobInfo
	// config layer in modctl's manifest
	blobConfig BlobConfig
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

type Manifest struct {
	Config BlobConfig   `json:"config"`
	Layers []BlobConfig `json:"layers"`
}

type BlobConfig struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      uint64 `json:"size"`
}

type fileInfo struct {
	name   string
	size   uint64
	offset uint64
}

type Option struct {
	Root         string `json:"root"`
	RegistryHost string `json:"registry_host"`
	Namespace    string `json:"namespace"`
	ImageName    string `json:"image_name"`
	Tag          string `json:"tag"`
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
	m, err := handler.extractManifest()
	if err != nil {
		return nil, errors.Wrap(err, "extract manifest failed")
	}
	handler.manifest = *m
	handler.setBlobs(m)
	handler.setBlobConfig(m)
	handler.setBlobsMap()

	return handler, nil
}

func GetOption(srcRef, modCtlRoot string) (*Option, error) {
	parts := strings.Split(srcRef, "/")
	if len(parts) != 3 {
		return nil, errors.New("invalid target ref")
	}
	nameTagParts := strings.Split(parts[2], ":")
	if len(nameTagParts) != 2 {
		return nil, errors.New("invalid target ref for name and tag")
	}
	opt := Option{
		Root:         modCtlRoot,
		RegistryHost: parts[0],
		Namespace:    parts[1],
		ImageName:    nameTagParts[0],
		Tag:          nameTagParts[1],
	}
	return &opt, nil
}

func (handler *Handler) Handle(ctx context.Context, file backend.File) ([]backend.Chunk, error) {
	chunks := []backend.Chunk{}
	needIgnore, blobInfo := handler.needIgnore(file.RelativePath)
	if needIgnore {
		return nil, nil
	}
	chunkSize := getChunkSizeByMediaType(blobInfo.mediaType)

	// read the tar file and get the meta of files
	files, err := handler.readBlob(filepath.Join(handler.root, file.RelativePath))
	if err != nil {
		return nil, errors.Wrap(err, "read blob failed")
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

func (handler *Handler) Backend(ctx context.Context) (*backend.Backend, error) {
	bkd := backend.Backend{
		Version: "v1",
	}
	bkd.Backends = []backend.BackendConfig{
		{
			Type: "registry",
		},
	}
	bkd.Blobs = handler.blobs
	return &bkd, nil
}

func (handler *Handler) GetConfig() ([]byte, error) {
	return handler.extractBlobs(handler.blobConfig.Digest)
}

func (handler *Handler) GetLayers() []BlobConfig {
	return handler.manifest.Layers
}

func (handler *Handler) setBlobs(m *Manifest) {
	handler.blobs = handler.convertToBlobs(m)
}

func (handler *Handler) setBlobConfig(m *Manifest) {
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

func (handler *Handler) extractManifest() (*Manifest, error) {
	tagPath := fmt.Sprintf(MANIFEST_PATH, handler.tag)
	manifestPath := filepath.Join(handler.root, REPOS_PATH, handler.registryHost, handler.namespace, handler.imageName, tagPath)
	line, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, errors.Wrap(err, "read manifest digest file failed")
	}
	content, err := handler.extractBlobs(string(line))
	if err != nil {
		return nil, errors.Wrap(err, "extract blobs failed")
	}

	var m Manifest
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

	blobPath := fmt.Sprintf(BLOB_PATH, digestSplit[0], digestSplit[1][:2], digestSplit[1])
	blobPath = filepath.Join(handler.root, blobPath)
	content, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "read  blobs file failed")
	}
	return content, nil

}

func (handler *Handler) convertToBlobs(m *Manifest) []backend.Blob {
	createBlob := func(layer BlobConfig) backend.Blob {
		digest := strings.Split(layer.Digest, ":")
		if len(digest) == 2 {
			layer.Digest = digest[1]
		}

		chunkSize := getChunkSizeByMediaType(layer.MediaType)
		return backend.Blob{
			Backend: 0,
			Config: backend.BlobConfig{
				MediaType: layer.MediaType,
				Digest:    layer.Digest,
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

func (handler *Handler) readBlob(path string) ([]fileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "open tar file failed")
	}
	defer f.Close()
	var files []fileInfo
	tarReader := tar.NewReader(f)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, errors.Wrap(err, "read tar file failed")
		}
		currentOffset, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, errors.Wrap(err, "seek tar file failed")
		}
		files = append(files, fileInfo{
			name:   header.Name,
			size:   uint64(header.Size),
			offset: uint64(currentOffset),
		})
	}
	return files, nil
}
