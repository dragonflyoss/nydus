package backend

import (
	"context"
)

type Backend struct {
	Version  string   `json:"version"`
	Backends []Config `json:"backends"`
	Blobs    []Blob   `json:"blobs"`
}

type Config struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
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
	BlobID                 string
	BlobSize               string
	FileSize               uint64
	ChunkSize              string
	Chunk0CompressedOffset uint64
	Type                   string
	Mode                   uint32
	Crcs                   string
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
}

type RemoteHanlder interface {
	// Handle handles the file and returns the object information.
	Handle(ctx context.Context) (*Backend, []FileAttribute, error)
}

type Chunk interface {
	ObjectID() uint32
	ObjectContent() interface{}
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
