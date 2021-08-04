package cache

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

const (
	chunkMapFileSuffix = ".chunk_map"
)

type Store interface {
	DelBlob(blob string) error
}

type CacheStore struct {
	cacheDir string
}

func NewStore(cacheDir string) *CacheStore {
	return &CacheStore{cacheDir: cacheDir}
}

func (cs *CacheStore) DelBlob(blob string) error {
	blobPath := cs.blobPath(blob)

	// Remove the blob chunkmap file named $blob_id.chunk_map first.
	chunkMapPath := blobPath + chunkMapFileSuffix
	if err := os.Remove(chunkMapPath); err != nil {
		// Older versions of nydusd do not support chunkmap, and there
		// is no chunkmap file generation, so just ignore the error.
		if !os.IsNotExist(err) {
			return errors.Wrapf(err, "remove blob chunkmap %v err", chunkMapPath)
		}
	}

	// Then remove the blob file named $blob_id.
	if err := os.Remove(blobPath); err != nil {
		return errors.Wrapf(err, "remove blob %v err", blobPath)
	}

	return nil
}

func (cs *CacheStore) blobPath(blob string) string {
	return filepath.Join(cs.cacheDir, blob)
}
