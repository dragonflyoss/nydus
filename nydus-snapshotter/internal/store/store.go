/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/store_mock.go -source store.go -package mocks

// Package store persists daemon instances and blob access times in bbolt,
// with a versioned bucket layout like containerd's metadata store.
package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/containerd/errdefs"
	bolt "go.etcd.io/bbolt"
)

const (
	// schemaVersion is the compatible layout version within the v1 bucket. A
	// change older binaries cannot read moves to a v2 bucket instead, as
	// containerd's metadata store does, so a newer version is read as is
	// after a rollback, refer to
	// https://github.com/containerd/containerd/blob/main/core/metadata/db.go.
	schemaVersion = 1

	// DefaultOpenTimeout bounds waiting for another process's file lock.
	DefaultOpenTimeout = 10 * time.Second
)

var (
	// bucketKeyV1 is the root bucket of schema version 1.
	bucketKeyV1 = []byte("v1")

	// bucketKeyInstances holds instances keyed by chain ID.
	bucketKeyInstances = []byte("instances")

	// bucketKeyBlobs holds blob access times keyed by blob ID.
	bucketKeyBlobs = []byte("blobs")

	// keyVersion holds the schema version in the root bucket.
	keyVersion = []byte("version")
)

// Instance is a daemon serving one image, keyed by its bootstrap chain ID.
type Instance struct {
	// ChainID is the chain ID of the image's bootstrap layer.
	ChainID string `json:"chain_id"`

	// Driver is the mount driver.
	Driver string `json:"driver"`

	// ImageRef is the image reference the daemon reads blobs from.
	ImageRef string `json:"image_ref"`

	// RegistryHost is the registry host credentials are matched against.
	RegistryHost string `json:"registry_host"`

	// Bootstrap is the bootstrap file the daemon serves.
	Bootstrap string `json:"bootstrap"`

	// Blobs are the IDs of the blobs the bootstrap references.
	Blobs []string `json:"blobs"`

	// Mountpoint is the daemon's mountpoint.
	Mountpoint string `json:"mountpoint"`

	// APISocket is the daemon's API socket.
	APISocket string `json:"api_socket"`

	// Unit is the daemon's systemd unit.
	Unit string `json:"unit"`

	// CreatedAt is when the instance was created.
	CreatedAt time.Time `json:"created_at"`
}

// Store persists daemon instances and blob access times.
type Store interface {
	// PutInstance creates or replaces an instance.
	PutInstance(instance *Instance) error

	// GetInstance returns the instance of a chain ID, errdefs.ErrNotFound when
	// missing.
	GetInstance(chainID string) (*Instance, error)

	// DeleteInstance deletes the instance of a chain ID; a missing one is not
	// an error.
	DeleteInstance(chainID string) error

	// ListInstances returns all instances.
	ListInstances() ([]*Instance, error)

	// TouchBlobs records t as the access time of the blobs.
	TouchBlobs(blobs []string, t time.Time) error

	// ListBlobs returns the access time of every recorded blob.
	ListBlobs() (map[string]time.Time, error)

	// DeleteBlobs forgets the blobs.
	DeleteBlobs(blobs []string) error

	// Close closes the store.
	Close() error
}

// store is a bbolt backed Store.
type store struct {
	// db is the bbolt database.
	db *bolt.DB
}

// New store interface. It opens or creates the bbolt file at path, waiting at
// most timeout for the file lock another process may hold.
func New(path string, timeout time.Duration) (Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("open store %s: %w", path, err)
	}

	s := &store{db: db}
	if err := db.Update(s.init); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

// init creates the buckets and checks the schema version.
func (s *store) init(tx *bolt.Tx) error {
	root, err := tx.CreateBucketIfNotExists(bucketKeyV1)
	if err != nil {
		return fmt.Errorf("create bucket %s: %w", bucketKeyV1, err)
	}

	if v := root.Get(keyVersion); v != nil {
		version, err := strconv.Atoi(string(v))
		if err != nil {
			return fmt.Errorf("decode schema version: %w", err)
		}

		if version < schemaVersion {
			return fmt.Errorf("unsupported store schema version %d, want at least %d", version, schemaVersion)
		}
	} else if err := root.Put(keyVersion, strconv.AppendInt(nil, schemaVersion, 10)); err != nil {
		return fmt.Errorf("put schema version: %w", err)
	}

	for _, key := range [][]byte{bucketKeyInstances, bucketKeyBlobs} {
		if _, err := root.CreateBucketIfNotExists(key); err != nil {
			return fmt.Errorf("create bucket %s: %w", key, err)
		}
	}

	return nil
}

// bucket returns a bucket under the root bucket.
func (s *store) bucket(tx *bolt.Tx, key []byte) *bolt.Bucket {
	return tx.Bucket(bucketKeyV1).Bucket(key)
}

// PutInstance creates or replaces an instance.
func (s *store) PutInstance(instance *Instance) error {
	value, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("encode instance %s: %w", instance.ChainID, err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return s.bucket(tx, bucketKeyInstances).Put([]byte(instance.ChainID), value)
	})
}

// GetInstance returns the instance of a chain ID, errdefs.ErrNotFound when
// missing.
func (s *store) GetInstance(chainID string) (*Instance, error) {
	var instance Instance
	if err := s.db.View(func(tx *bolt.Tx) error {
		value := s.bucket(tx, bucketKeyInstances).Get([]byte(chainID))
		if value == nil {
			return fmt.Errorf("instance %s: %w", chainID, errdefs.ErrNotFound)
		}

		if err := json.Unmarshal(value, &instance); err != nil {
			return fmt.Errorf("decode instance %s: %w", chainID, err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return &instance, nil
}

// DeleteInstance deletes the instance of a chain ID; a missing one is not an
// error.
func (s *store) DeleteInstance(chainID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.bucket(tx, bucketKeyInstances).Delete([]byte(chainID))
	})
}

// ListInstances returns all instances.
func (s *store) ListInstances() ([]*Instance, error) {
	var instances []*Instance
	if err := s.db.View(func(tx *bolt.Tx) error {
		return s.bucket(tx, bucketKeyInstances).ForEach(func(key, value []byte) error {
			var instance Instance
			if err := json.Unmarshal(value, &instance); err != nil {
				return fmt.Errorf("decode instance %s: %w", key, err)
			}

			instances = append(instances, &instance)
			return nil
		})
	}); err != nil {
		return nil, err
	}

	return instances, nil
}

// TouchBlobs records t as the access time of the blobs.
func (s *store) TouchBlobs(blobs []string, t time.Time) error {
	value, err := t.UTC().MarshalBinary()
	if err != nil {
		return fmt.Errorf("encode time: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := s.bucket(tx, bucketKeyBlobs)
		for _, blob := range blobs {
			if err := b.Put([]byte(blob), value); err != nil {
				return fmt.Errorf("put blob %s: %w", blob, err)
			}
		}

		return nil
	})
}

// ListBlobs returns the access time of every recorded blob.
func (s *store) ListBlobs() (map[string]time.Time, error) {
	blobs := make(map[string]time.Time)
	if err := s.db.View(func(tx *bolt.Tx) error {
		return s.bucket(tx, bucketKeyBlobs).ForEach(func(key, value []byte) error {
			var t time.Time
			if err := t.UnmarshalBinary(value); err != nil {
				return fmt.Errorf("decode blob %s time: %w", key, err)
			}

			blobs[string(key)] = t
			return nil
		})
	}); err != nil {
		return nil, err
	}

	return blobs, nil
}

// DeleteBlobs forgets the blobs.
func (s *store) DeleteBlobs(blobs []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := s.bucket(tx, bucketKeyBlobs)
		for _, blob := range blobs {
			if err := b.Delete([]byte(blob)); err != nil {
				return fmt.Errorf("delete blob %s: %w", blob, err)
			}
		}

		return nil
	})
}

// Close closes the store.
func (s *store) Close() error {
	return s.db.Close()
}
