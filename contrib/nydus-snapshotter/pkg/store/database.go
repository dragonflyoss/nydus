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

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
)

// Bucket names
var (
	daemonsBucketName = []byte("daemons") // Contains daemon info <daemon_id>=<daemon>
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
func NewDatabase(dbfile string) (*Database, error) {
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
func (d *Database) Cleanup(ctx context.Context) error {
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
