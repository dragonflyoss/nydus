package cache

import (
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/store"
)

type DB interface {
	AddSnapshot(imageID string, blobs []string) error
	DelSnapshot(imageID string) error
	GC(delFunc func(blob string) error) ([]string, error)
}

var _ DB = &store.CacheStore{}
