package cache

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
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
	if err := os.Remove(blobPath); err != nil {
		return errors.Wrapf(err, "remove blob %v err", blobPath)
	}
	return nil
}

func (cs *CacheStore) blobPath(blob string) string {
	return filepath.Join(cs.cacheDir, blob)
}
