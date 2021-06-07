/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package store

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
)

type DaemonStore struct {
	sync.Mutex
	idxBySnapshotID map[string]*daemon.Daemon // index by snapshot ID per image
	idxByID         map[string]*daemon.Daemon // index by ID per daemon include upgraded daemon
	daemons         []*daemon.Daemon          // all daemon
	db              *Database                 // save daemons in database
}

func NewDaemonStore(db *Database) (*DaemonStore, error) {
	return &DaemonStore{
		idxBySnapshotID: make(map[string]*daemon.Daemon),
		idxByID:         make(map[string]*daemon.Daemon),
		db:              db,
	}, nil
}

func (s *DaemonStore) Get(id string) (*daemon.Daemon, error) {
	s.Lock()
	defer s.Unlock()
	if d, ok := s.idxByID[id]; ok {
		return d, nil
	}
	return nil, os.ErrNotExist
}

func (s *DaemonStore) GetBySnapshot(snapshotID string) (*daemon.Daemon, error) {
	s.Lock()
	defer s.Unlock()
	if d, ok := s.idxBySnapshotID[snapshotID]; ok {
		return d, nil
	}

	return nil, os.ErrNotExist
}

func (s *DaemonStore) List() []*daemon.Daemon {
	s.Lock()
	defer s.Unlock()
	if s.daemons == nil {
		return nil
	}
	res := make([]*daemon.Daemon, len(s.daemons))
	copy(res, s.daemons)
	return res
}

func (s *DaemonStore) Size() int {
	s.Lock()
	defer s.Unlock()
	return len(s.daemons)
}

func (s *DaemonStore) Add(d *daemon.Daemon) error {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.idxBySnapshotID[d.SnapshotID]; ok {
		return fmt.Errorf("daemon of snapshotID %s already exists", d.SnapshotID)
	}

	s.daemons = append(s.daemons, d)
	s.idxBySnapshotID[d.SnapshotID] = d
	s.idxByID[d.ID] = d

	// save daemon info in case snapshotter restarts so that we can restore the
	// daemon structs and reconnect the daemons.
	return s.db.SaveDaemon(context.TODO(), d)
}

func (s *DaemonStore) Delete(d *daemon.Daemon) error {
	s.Lock()
	defer s.Unlock()
	delete(s.idxBySnapshotID, d.SnapshotID)
	delete(s.idxByID, d.ID)
	s.daemons = s.filterOutDeletedDaemon(d)

	return s.db.DeleteDaemon(context.TODO(), d.ID)
}

func (s *DaemonStore) filterOutDeletedDaemon(d *daemon.Daemon) []*daemon.Daemon {
	res := s.daemons[:0]
	for _, md := range s.daemons {
		if md == d {
			continue
		}
		res = append(res, md)
	}
	return res
}

func (s *DaemonStore) WalkDaemons(ctx context.Context, cb func(d *daemon.Daemon) error) error {
	return s.db.WalkDaemons(ctx, cb)
}

func (s *DaemonStore) CleanupDaemons(ctx context.Context) error {
	return s.db.CleanupDaemons(ctx)
}
