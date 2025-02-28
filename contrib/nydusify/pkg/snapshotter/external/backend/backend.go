package backend

import (
	"context"
)

type Backend struct {
	Version  string          `json:"version"`
	Backends []BackendConfig `json:"backends"`
	Blobs    []Blob          `json:"blobs"`
}

type BackendConfig struct {
	Type   string            `json:"type"`
	Config map[string]string `json:"config,omitempty"`
}

type Blob struct {
	Backend int        `json:"backend"`
	Config  BlobConfig `json:"config"`
}

type BlobConfig struct {
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Size      string `json:"size"`
	ChunkSize string `json:"chunk_size"`
}

type Result struct {
	Chunks  []Chunk
	Files   []FileAttribute
	Backend Backend
}

type FileAttribute struct {
	RelativePath           string
	BlobIndex              uint32
	BlobId                 string
	BlobSize               string
	ChunkSize              string
	Chunk0CompressedOffset uint64
	Type                   string
}

type File struct {
	RelativePath string
	Size         int64
}

// Handler is the interface for backend handler.
type Handler interface {
	// Backend returns the backend information.
	Backend(ctx context.Context) (*Backend, error)
	// Handle handles the file and returns the object information.
	Handle(ctx context.Context, file File) ([]Chunk, error)
	// Get the config descriptor in manifest
	GetConfig() ([]byte, error)
}

type Chunk interface {
	// 存储blobIndex
	ObjectID() uint32
	// 存储原始文件名， ChunkSize
	ObjectContent() interface{}
	// 存储chunk在blob tar文件中的偏移
	ObjectOffset() uint64
	FilePath() string
	LimitChunkSize() string
	BlobDigest() string
	BlobSize() string
}

// SplitObjectOffsets splits the total size into object offsets
// with the specified chunk size.
func SplitObjectOffsets(totalSize, chunkSize int64) []uint64 {
	objectOffsets := []uint64{}
	if chunkSize <= 0 {
		return objectOffsets
	}

	chunkN := totalSize / chunkSize

	for i := int64(0); i < chunkN; i++ {
		objectOffsets = append(objectOffsets, uint64(i*chunkSize))
	}

	if totalSize%chunkSize > 0 {
		objectOffsets = append(objectOffsets, uint64(chunkN*chunkSize))
	}

	return objectOffsets
}
