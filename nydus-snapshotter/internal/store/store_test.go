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
		Bootstrap:    "/var/lib/containerd-nydus-v3/nydusd/1/image.boot",
		Blobs:        []string{"a", "b"},
		Mountpoint:   "/var/lib/containerd-nydus-v3/nydusd/1/mnt",
		APISocket:    "/run/containerd-nydus-v3/nydusd/1.sock",
		Unit:         "nydusd-1.service",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}

	mockTime = time.Unix(1800000000, 0).UTC()
)

func TestStore_Instance(t *testing.T) {
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
			assert.NoError(t, err)
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(filepath.Join(t.TempDir(), "nydusd.db"), DefaultOpenTimeout)
			assert.NoError(t, err)
			defer s.Close()
			tc.expect(t, s)
		})
	}
}

func TestStore_New(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, path string)
		expect func(t *testing.T, s Store, err error)
	}{
		{
			name:  "reopen store",
			setup: func(t *testing.T, path string) {},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(s.Close())
			},
		},
		{
			name: "store held by another process",
			setup: func(t *testing.T, path string) {
				s, err := New(path, DefaultOpenTimeout)
				assert.NoError(t, err)
				t.Cleanup(func() { s.Close() })
			},
			expect: func(t *testing.T, s Store, err error) {
				assert.ErrorContains(t, err, "timeout")
			},
		},
		{
			name: "read a newer compatible schema version",
			setup: func(t *testing.T, path string) {
				writeVersion(t, path, "2")
			},
			expect: func(t *testing.T, s Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(s.Close())
			},
		},
		{
			name: "unsupported schema version",
			setup: func(t *testing.T, path string) {
				writeVersion(t, path, "0")
			},
			expect: func(t *testing.T, s Store, err error) {
				assert.ErrorContains(t, err, "unsupported store schema version 0")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nydusd.db")
			tc.setup(t, path)
			s, err := New(path, 100*time.Millisecond)
			tc.expect(t, s, err)
		})
	}
}

func writeVersion(t *testing.T, path, version string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	assert.NoError(t, err)
	assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucket(bucketKeyV1)
		if err != nil {
			return err
		}

		return root.Put(keyVersion, []byte(version))
	}))
	assert.NoError(t, db.Close())
}
