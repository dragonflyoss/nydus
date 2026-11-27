/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

var (
	mockInstance = &Instance{
		ChainID:      "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		Driver:       "fuse",
		ImageRef:     "registry.example.com/team/app:v1-nydus-v3",
		RegistryHost: "registry.example.com",
		Bootstrap:    "/var/lib/nydus-snapshotter/nydusd/1/image.boot",
		Blobs:        []string{"a", "b"},
		Mountpoint:   "/var/lib/nydus-snapshotter/nydusd/1/mnt",
		APISocket:    "/run/nydus-snapshotter/nydusd/1.sock",
		Unit:         "nydusd-1.service",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}

	mockTime = time.Unix(1800000000, 0).UTC()
)

func TestStore_Instances(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Store)
	}{
		{
			name: "put and get instance",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				assert.NoError(s.PutInstance(mockInstance))
				instance, err := s.GetInstance(mockInstance.ChainID)
				assert.NoError(err)
				assert.Equal(mockInstance, instance)
			},
		},
		{
			name: "instance does not exist",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				_, err := s.GetInstance(mockInstance.ChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "list and delete instances",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				assert.NoError(s.PutInstance(mockInstance))
				instances, err := s.ListInstances()
				assert.NoError(err)
				assert.Equal([]*Instance{mockInstance}, instances)
				assert.NoError(s.DeleteInstance(mockInstance.ChainID))
				assert.NoError(s.DeleteInstance(mockInstance.ChainID))
				instances, err = s.ListInstances()
				assert.NoError(err)
				assert.Empty(instances)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(filepath.Join(t.TempDir(), "nydusd.db"), DefaultOpenTimeout)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			defer s.Close()
			tc.expect(t, s)
		})
	}
}

func TestStore_Blobs(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Store)
	}{
		{
			name: "touch and list blobs",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				assert.NoError(s.TouchBlobs([]string{"a", "b"}, mockTime))
				blobs, err := s.ListBlobs()
				assert.NoError(err)
				assert.Equal(map[string]time.Time{"a": mockTime, "b": mockTime}, blobs)
			},
		},
		{
			name: "delete blobs",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				assert.NoError(s.TouchBlobs([]string{"a", "b"}, mockTime))
				assert.NoError(s.DeleteBlobs([]string{"a", "c"}))
				blobs, err := s.ListBlobs()
				assert.NoError(err)
				assert.Equal(map[string]time.Time{"b": mockTime}, blobs)
			},
		},
		{
			name: "blob without an ID",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				assert.ErrorContains(s.TouchBlobs([]string{""}, mockTime), "put blob ")
				blobs, err := s.ListBlobs()
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name: "blob that is a bucket",
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				assert.NoError(s.(*store).db.Update(func(tx *bolt.Tx) error {
					_, err := tx.Bucket(bucketKeyV1).Bucket(bucketKeyBlobs).CreateBucket([]byte("a"))
					return err
				}))
				assert.ErrorContains(s.DeleteBlobs([]string{"a"}), "delete blob a")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(filepath.Join(t.TempDir(), "nydusd.db"), DefaultOpenTimeout)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			defer s.Close()
			tc.expect(t, s)
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, path string)
		expect  func(t *testing.T, s Store, err error)
	}{
		{
			name: "reopen store",
			prepare: func(t *testing.T, path string) {
				s, err := New(path, DefaultOpenTimeout)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.NoError(t, s.PutInstance(mockInstance))
				assert.NoError(t, s.Close())
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					return
				}

				instance, err := s.GetInstance(mockInstance.ChainID)
				assert.NoError(err)
				assert.Equal(mockInstance, instance)
				assert.NoError(s.Close())
			},
		},
		{
			name: "store held by another process",
			prepare: func(t *testing.T, path string) {
				s, err := New(path, DefaultOpenTimeout)
				assert.NoError(t, err)
				t.Cleanup(func() { s.Close() })
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "timeout")
			},
		},
		{
			name: "read a newer compatible schema version",
			prepare: func(t *testing.T, path string) {
				db, err := bolt.Open(path, 0o600, nil)
				assert.NoError(t, err)
				assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
					root, err := tx.CreateBucket(bucketKeyV1)
					if err != nil {
						return err
					}

					return root.Put(bucketKeyDBVersion, []byte("2"))
				}))
				assert.NoError(t, db.Close())
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(s.Close())
			},
		},
		{
			name: "schema version that is no number",
			prepare: func(t *testing.T, path string) {
				db, err := bolt.Open(path, 0o600, nil)
				assert.NoError(t, err)
				assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
					root, err := tx.CreateBucket(bucketKeyV1)
					if err != nil {
						return err
					}

					return root.Put(bucketKeyDBVersion, []byte("one"))
				}))
				assert.NoError(t, db.Close())
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode schema version")
				assert.Nil(s)
			},
		},
		{
			name: "unsupported schema version",
			prepare: func(t *testing.T, path string) {
				db, err := bolt.Open(path, 0o600, nil)
				assert.NoError(t, err)
				assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
					root, err := tx.CreateBucket(bucketKeyV1)
					if err != nil {
						return err
					}

					return root.Put(bucketKeyDBVersion, []byte("0"))
				}))
				assert.NoError(t, db.Close())
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported store schema version 0")
			},
		},
		{
			name: "bucket name held by a value",
			prepare: func(t *testing.T, path string) {
				db, err := bolt.Open(path, 0o600, nil)
				assert.NoError(t, err)
				assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
					root, err := tx.CreateBucket(bucketKeyV1)
					if err != nil {
						return err
					}

					return root.Put(bucketKeyInstances, []byte("value"))
				}))
				assert.NoError(t, db.Close())
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create bucket "+string(bucketKeyInstances))
				assert.Nil(s)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nydusd.db")
			tc.prepare(t, path)
			s, err := New(path, 100*time.Millisecond)
			tc.expect(t, s, err)
		})
	}
}

func TestStore_decode(t *testing.T) {
	tests := []struct {
		name   string
		bucket []byte
		expect func(t *testing.T, s Store)
	}{
		{
			name:   "instance that does not decode",
			bucket: bucketKeyInstances,
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				_, err := s.GetInstance(mockInstance.ChainID)
				assert.ErrorContains(err, "decode instance "+mockInstance.ChainID)
				_, err = s.ListInstances()
				assert.ErrorContains(err, "decode instance "+mockInstance.ChainID)
			},
		},
		{
			name:   "blob time that does not decode",
			bucket: bucketKeyBlobs,
			expect: func(t *testing.T, s Store) {
				assert := assert.New(t)
				_, err := s.ListBlobs()
				assert.ErrorContains(err, "decode blob "+mockInstance.ChainID+" time")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(filepath.Join(t.TempDir(), "nydusd.db"), DefaultOpenTimeout)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			defer s.Close()
			assert.NoError(t, s.(*store).db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucketKeyV1).Bucket(tc.bucket).Put([]byte(mockInstance.ChainID), []byte("{"))
			}))

			tc.expect(t, s)
		})
	}
}
