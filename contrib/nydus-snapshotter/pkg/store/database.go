/*
 * Copyright (c) 2021. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
)

const (
	databaseFileName = "nydus.db"
)

// Bucket names
var (
	daemonsBucketName = []byte("daemons") // Contains daemon info <daemon_id>=<daemon>

	cachesBucketName   = []byte("caches")
	snapshotBucketName = []byte("snapshots")

	blobBucketName = []byte("blobs")
)

var (
	// ErrNotFound errors when the querying object not exists
	ErrNotFound = errors.New("object not found")
	// ErrAlreadyExists errors when duplicated object found
	ErrAlreadyExists = errors.New("object already exists")
)

// Database keeps infos that need to survive among snapshotter restart
type Database struct {
	db *bolt.DB
}

// NewDatabase creates a new or open existing database file
func NewDatabase(rootDir string) (*Database, error) {
	dbfile := filepath.Join(rootDir, databaseFileName)
	if err := ensureDirectory(filepath.Dir(dbfile)); err != nil {
		return nil, err
	}

	db, err := bolt.Open(dbfile, 0600, nil)
	if err != nil {
		return nil, err
	}
	d := &Database{db: db}
	if err := d.initDatabase(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize database")
	}
	return d, nil
}

func ensureDirectory(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0700)
	}

	return nil
}

func (d *Database) initDatabase() error {
	return d.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(daemonsBucketName); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(cachesBucketName); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(snapshotBucketName); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(blobBucketName); err != nil {
			return err
		}
		return nil
	})
}

// SaveDaemon saves daemon record from database
func (d *Database) SaveDaemon(ctx context.Context, dmn *daemon.Daemon) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(daemonsBucketName)

		var existing daemon.Daemon
		if err := getObject(bucket, dmn.ID, &existing); err == nil {
			return ErrAlreadyExists
		}

		return putObject(bucket, dmn.ID, dmn)
	})
}

// DeleteDaemon deletes daemon record from database
func (d *Database) DeleteDaemon(ctx context.Context, id string) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(daemonsBucketName)

		if err := bucket.Delete([]byte(id)); err != nil {
			return errors.Wrapf(err, "failed to delete daemon for %q", id)
		}

		return nil
	})
}

// WalkDaemons iterates all daemon records and invoke callback on each
func (d *Database) WalkDaemons(ctx context.Context, cb func(info *daemon.Daemon) error) error {
	return d.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(daemonsBucketName)
		return bucket.ForEach(func(key, value []byte) error {
			dmn := &daemon.Daemon{}
			if err := json.Unmarshal(value, dmn); err != nil {
				return errors.Wrapf(err, "failed to unmarshal %s", key)
			}

			return cb(dmn)
		})
	})
}

// Cleanup deletes all daemon records
func (d *Database) CleanupDaemons(ctx context.Context) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(daemonsBucketName)

		return bucket.ForEach(func(k, _ []byte) error {
			return bucket.Delete(k)
		})
	})
}

func putObject(bucket *bolt.Bucket, key string, obj interface{}) error {
	keyBytes := []byte(key)

	if bucket.Get(keyBytes) != nil {
		return errors.Errorf("object with key %q already exists", key)
	}

	value, err := json.Marshal(obj)
	if err != nil {
		return errors.Wrapf(err, "failed to marshall object with key %q", key)
	}

	if err := bucket.Put(keyBytes, value); err != nil {
		return errors.Wrapf(err, "failed to insert object with key %q", key)
	}

	return nil
}

func updateObject(bucket *bolt.Bucket, key string, obj interface{}) error {
	keyBytes := []byte(key)

	value, err := json.Marshal(obj)
	if err != nil {
		return errors.Wrapf(err, "failed to marshall object with key %q", key)
	}

	if err := bucket.Put(keyBytes, value); err != nil {
		return errors.Wrapf(err, "failed to insert object with key %q", key)
	}

	return nil
}

func getObject(bucket *bolt.Bucket, key string, obj interface{}) error {
	if obj == nil {
		return errors.Errorf("invalid arg: obj cannot be nil")
	}

	value := bucket.Get([]byte(key))
	if value == nil {
		return ErrNotFound
	}

	if err := json.Unmarshal(value, obj); err != nil {
		return errors.Wrapf(err, "failed to unmarshall object with key %q", key)
	}

	return nil
}

func (d *Database) addSnapshot(imageID string, snapshot *Snapshot) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		cbkt := tx.Bucket(cachesBucketName)
		sbkt, err := cbkt.CreateBucketIfNotExists(snapshotBucketName)
		if err != nil {
			return err
		}
		exist := &Snapshot{}

		if err := getObject(sbkt, imageID, exist); err == nil {
			exist.Blobs = snapshot.Blobs
			exist.UpdateAt = time.Now()
			return updateObject(sbkt, imageID, exist)
		}

		return putObject(sbkt, imageID, snapshot)
	})
}

func (d *Database) addBlob(blobID string, blob *Blob) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		cbkt := tx.Bucket(cachesBucketName)
		bbkt, err := cbkt.CreateBucketIfNotExists(blobBucketName)
		if err != nil {
			return err
		}

		exist := &Blob{}
		if err := getObject(bbkt, blobID, exist); err == nil {
			exist.UpdateAt = time.Now()
			return updateObject(bbkt, blobID, exist)
		}
		return putObject(bbkt, blobID, blob)
	})
}

func (d *Database) delSnapshot(imageID string) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		cbkt := tx.Bucket(cachesBucketName)
		sbkt, err := cbkt.CreateBucketIfNotExists(snapshotBucketName)
		if err != nil {
			return err
		}
		if err := sbkt.Delete([]byte(imageID)); err != nil {
			return err
		}
		return nil
	})
}

func (d *Database) delBlob(blobID string) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		cbkt := tx.Bucket(cachesBucketName)
		bbkt, err := cbkt.CreateBucketIfNotExists(blobBucketName)
		if err != nil {
			return err
		}
		if err := bbkt.Delete([]byte(blobID)); err != nil {
			return err
		}
		return nil
	})
}

func (d *Database) getMarked() (map[string]struct{}, error) {
	var results = make(map[string]struct{})
	if err := d.db.View(func(tx *bolt.Tx) error {
		cbkt := tx.Bucket(cachesBucketName)
		sbkt := cbkt.Bucket(snapshotBucketName)

		return sbkt.ForEach(func(k, v []byte) error {
			snapshot := &Snapshot{}
			if err := json.Unmarshal(v, snapshot); err != nil {
				return err
			}
			for _, blobID := range snapshot.Blobs {
				results[blobID] = struct{}{}
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}
	return results, nil
}

func (d *Database) walkBlobs(filter func(blobID string) bool) ([]string, error) {
	var results []string
	if err := d.db.View(func(tx *bolt.Tx) error {
		cbkt := tx.Bucket(cachesBucketName)
		bbkt := cbkt.Bucket(blobBucketName)

		if err := bbkt.ForEach(func(k, v []byte) error {
			key := string(k)
			if filter(key) {
				results = append(results, key)
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return results, nil
}

func (d *Database) getUnusedBlobs() ([]string, error) {
	blobSeens, err := d.getMarked()
	if err != nil {
		return nil, err
	}
	return d.walkBlobs(func(blob string) bool {
		if _, ok := blobSeens[blob]; !ok {
			return true
		}
		return false
	})
}
