// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/efc4166e93a22804b90e27c912eff7ecc0a12dfc/store/fs.go#L593-L650
package fs

import (
	"fmt"
	"sync"

	"golang.org/x/sync/singleflight"
)

// idMap manages uint32 IDs with automatic GC for releasable objects.
type idMap struct {
	m        map[uint32]releasable
	max      uint32
	mu       sync.Mutex
	cleanupG singleflight.Group
}

// port from stargz-snapshooter.
// add reserves an unique uint32 object for the provided releasable object.
// when that object become releasable, that ID will be reused for other objects.
func (m *idMap) add(p func(uint32) (releasable, error)) error {
	m.cleanupG.Do("cleanup", func() (interface{}, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		max := uint32(0)
		for i := uint32(0); i <= m.max; i++ {
			if e, ok := m.m[i]; ok {
				if e.releasable() {
					delete(m.m, i)
				} else {
					max = i
				}
			}
		}
		m.max = max
		return nil, nil
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.m == nil {
		m.m = make(map[uint32]releasable)
	}

	for i := uint32(0); i <= ^uint32(0); i++ {
		if i == 0 || i == 1 {
			continue
		}
		e, ok := m.m[i]
		if !ok || e.releasable() {
			r, err := p(i)
			if err != nil {
				return err
			}
			if m.max < i {
				m.max = i
			}
			m.m[i] = r
			return nil
		}
	}
	return fmt.Errorf("no ID is usable")
}
