package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type Blob struct {
	CreateAt time.Time
	UpdateAt time.Time
}

type Snapshot struct {
	ImageID  string
	Blobs    []string
	CreateAt time.Time
	UpdateAt time.Time
}
type CacheStore struct {
	sync.Mutex
	*Database
}

func NewCacheStore(db *Database) (*CacheStore, error) {
	return &CacheStore{Database: db}, nil
}

func (cs *CacheStore) AddSnapshot(imageID string, blobs []string) error {
	cs.Lock()
	defer cs.Unlock()

	ss := &Snapshot{
		ImageID:  imageID,
		Blobs:    blobs,
		CreateAt: time.Now(),
		UpdateAt: time.Now(),
	}
	if err := cs.Database.addSnapshot(imageID, ss); err != nil {
		return err
	}
	for _, id := range blobs {
		blob := &Blob{
			CreateAt: time.Now(),
			UpdateAt: time.Now(),
		}
		if err := cs.Database.addBlob(id, blob); err != nil {
			return err
		}
	}
	return nil
}

func (cs *CacheStore) DelSnapshot(imageID string) error {
	cs.Lock()
	defer cs.Unlock()

	return cs.Database.delSnapshot(imageID)

}

func (cs *CacheStore) GC(delFunc func(blob string) error) ([]string, error) {
	cs.Lock()
	defer cs.Unlock()

	delBlobs, err := cs.Database.getUnusedBlobs()
	if err != nil {
		return nil, err
	}
	var errs []error
	errMsg := func(errs []error) string {
		msg := "errors: "
		for i, e := range errs {
			msg += fmt.Sprintf("error %d: %s\t", i, e.Error())
		}
		return msg
	}
	for _, blob := range delBlobs {
		if err := cs.Database.delBlob(blob); err != nil {
			errs = append(errs, err)
		}
		if err := delFunc(blob); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return nil, errors.New(errMsg(errs))
	}
	return delBlobs, nil
}
