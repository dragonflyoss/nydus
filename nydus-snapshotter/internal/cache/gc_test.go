/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

var (
	mockNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

	mockOld = mockNow.Add(-time.Hour)

	mockGCConfig = config.GCConfig{
		Interval: config.Duration(time.Minute),
		Policy: config.GCPolicyConfig{
			BlobTTL:                  config.Duration(24 * time.Hour),
			DiskHighThresholdPercent: 80,
			DiskLowThresholdPercent:  60,
		},
	}

	mockLowUsage = diskUsage{total: 100 << 20, used: 10 << 20}
)

func TestGC_RunGC(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]time.Time
		touched   map[string]time.Time
		running   []string
		committed []string
		prepare   func(t *testing.T, g *gc)
		expect    func(t *testing.T, dir string, s store.Store, err error)
	}{
		{
			name:  "skip a round while a daemon starts",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				lock := g.StartLock()
				lock.Lock()
				t.Cleanup(lock.Unlock)
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errBusy)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "keep a blob whose daemon started after the candidates were picked",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				calls := 0
				g.running = func(context.Context) (map[string]struct{}, error) {
					calls++
					if calls == 1 {
						return map[string]struct{}{}, nil
					}

					return map[string]struct{}{"a": {}}, nil
				}
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:      "evict orphan blob",
			files:     map[string]time.Time{"a.blob.data": mockOld, "a.blob.meta": mockOld, "a.group.map": mockOld},
			committed: []string{"b"},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(dir, "a.blob.data"))
				assert.NoFileExists(filepath.Join(dir, "a.blob.meta"))
				assert.NoFileExists(filepath.Join(dir, "a.group.map"))
			},
		},
		{
			name:      "keep blob of committed image within ttl",
			files:     map[string]time.Time{"a.blob.data": mockOld},
			touched:   map[string]time.Time{"a": mockOld},
			committed: []string{"a"},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:      "evict blob past ttl and forget it",
			files:     map[string]time.Time{"a.blob.data": mockOld},
			touched:   map[string]time.Time{"a": mockNow.Add(-48 * time.Hour)},
			committed: []string{"a"},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(dir, "a.blob.data"))
				blobs, err := s.ListBlobs()
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name:    "keep blob of running daemon",
			files:   map[string]time.Time{"a.blob.data": mockOld},
			touched: map[string]time.Time{"a": mockNow.Add(-48 * time.Hour)},
			running: []string{"a"},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "keep recently written orphan",
			files: map[string]time.Time{"a.blob.meta": mockNow.Add(-time.Minute)},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "a.blob.meta"))
			},
		},
		{
			name:      "future access time counts as now",
			files:     map[string]time.Time{"a.blob.data": mockOld},
			touched:   map[string]time.Time{"a": mockNow.Add(24 * 365 * time.Hour)},
			committed: []string{"a"},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "remove stale temporary meta",
			files: map[string]time.Time{".blob-meta-123.tmp": mockOld, ".blob-meta-456.tmp": mockNow},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(dir, ".blob-meta-123.tmp"))
				assert.FileExists(filepath.Join(dir, ".blob-meta-456.tmp"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, mtime := range tc.files {
				path := filepath.Join(dir, name)
				assert.NoError(t, os.WriteFile(path, []byte("data"), 0o644))
				assert.NoError(t, os.Chtimes(path, mtime, mtime))
			}

			s := newTestStore(t)
			for id, at := range tc.touched {
				assert.NoError(t, s.TouchBlobs([]string{id}, at))
			}

			g := newTestGC(dir, s, mockLowUsage)
			g.running = blobSet(tc.running)
			g.committed = blobSet(tc.committed)
			if tc.prepare != nil {
				tc.prepare(t, g)
			}

			tc.expect(t, dir, s, g.RunGC(t.Context()))
		})
	}
}

func TestGC_evict(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, g *gc, dir string)
	}{
		{
			name: "keep blob whose prefetch lock is held",
			expect: func(t *testing.T, g *gc, dir string) {
				assert := assert.New(t)
				lock := filepath.Join(dir, "a.prefetch.lock")
				assert.NoError(os.WriteFile(lock, nil, 0o644))
				f, err := os.Open(lock)
				assert.NoError(err)
				defer f.Close()
				assert.NoError(unix.Flock(int(f.Fd()), unix.LOCK_EX))

				b := &blob{id: "a", files: []string{lock}}
				assert.False(g.evict(t.Context(), b, reasonOrphan))
				assert.FileExists(lock)
			},
		},
		{
			name: "evict blob whose prefetch lock is free",
			expect: func(t *testing.T, g *gc, dir string) {
				assert := assert.New(t)
				lock := filepath.Join(dir, "a.prefetch.lock")
				assert.NoError(os.WriteFile(lock, nil, 0o644))

				b := &blob{id: "a", files: []string{lock}}
				assert.True(g.evict(t.Context(), b, reasonOrphan))
				assert.NoFileExists(lock)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.expect(t, newTestGC(dir, newTestStore(t), mockLowUsage), dir)
		})
	}
}

func TestGC_overWatermark(t *testing.T) {
	tests := []struct {
		name      string
		usage     diskUsage
		threshold config.Size
		cached    uint64
		picked    []eviction
		lru       []*blob
		expect    func(t *testing.T, evictions []eviction, err error)
	}{
		{
			name:      "keep a cache under its threshold on a full disk",
			usage:     diskUsage{total: 100, used: 99},
			threshold: 1000,
			cached:    10,
			lru:       []*blob{{id: "a", size: 10, accessTime: mockOld}},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(evictions)
			},
		},
		{
			name:      "evict a cache over its threshold down to the low watermark",
			usage:     diskUsage{total: 100, used: 10},
			threshold: 100,
			cached:    90,
			lru: []*blob{
				{id: "newer", size: 20, accessTime: mockNow.Add(-time.Minute)},
				{id: "older", size: 20, accessTime: mockNow.Add(-2 * time.Hour)},
				{id: "oldest", size: 20, accessTime: mockNow.Add(-3 * time.Hour)},
			},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"oldest", "older"}, evictionIDs(evictions))
			},
		},
		{
			name:  "keep cache under the high watermark",
			usage: diskUsage{total: 100, used: 79},
			lru:   []*blob{{id: "a", size: 10, accessTime: mockOld}},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(evictions)
			},
		},
		{
			name:  "evict least recently used down to the low watermark",
			usage: diskUsage{total: 100, used: 90},
			lru: []*blob{
				{id: "recent", size: 20, accessTime: mockNow.Add(-time.Minute)},
				{id: "oldest", size: 20, accessTime: mockNow.Add(-3 * time.Hour)},
				{id: "older", size: 20, accessTime: mockNow.Add(-2 * time.Hour)},
			},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"oldest", "older"}, evictionIDs(evictions))
			},
		},
		{
			name:   "count picked blobs as freed",
			usage:  diskUsage{total: 100, used: 90},
			picked: []eviction{{blob: &blob{id: "orphan", size: 30}, reason: reasonOrphan}},
			lru:    []*blob{{id: "a", size: 20, accessTime: mockOld}},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(evictions)
			},
		},
		{
			name:  "never evict more than the cache holds",
			usage: diskUsage{total: 100, used: 99},
			lru:   []*blob{{id: "a", size: 5, accessTime: mockOld}},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"a"}, evictionIDs(evictions))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGC(t.TempDir(), nil, tc.usage)
			g.cfg.Policy.DiskThreshold = tc.threshold
			evictions, err := g.overWatermark(t.Context(), tc.cached, tc.picked, tc.lru)
			tc.expect(t, evictions, err)
		})
	}
}

func TestBlob_add(t *testing.T) {
	tests := []struct {
		name   string
		link   bool
		expect func(t *testing.T, b *blob)
	}{
		{
			name: "count a file's blocks",
			expect: func(t *testing.T, b *blob) {
				assert.NotZero(t, b.size)
			},
		},
		{
			name: "count nothing for a file linked elsewhere",
			link: true,
			expect: func(t *testing.T, b *blob) {
				assert.Zero(t, b.size)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.blob.meta")
			assert.NoError(t, os.WriteFile(path, make([]byte, 8192), 0o644))
			if tc.link {
				assert.NoError(t, os.Link(path, filepath.Join(dir, "image.blob.meta")))
			}

			info, err := os.Stat(path)
			assert.NoError(t, err)
			b := &blob{id: "a"}
			b.add(path, info)
			tc.expect(t, b)
		})
	}
}

func newTestGC(dir string, s store.Store, usage diskUsage) *gc {
	return &gc{
		cfg:    mockGCConfig,
		dir:    dir,
		store:  s,
		now:    func() time.Time { return mockNow },
		statfs: func(string) (diskUsage, error) { return usage, nil },
	}
}

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "nydusd.db"), store.DefaultOpenTimeout)
	assert.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func blobSet(ids []string) BlobsFunc {
	return func(context.Context) (map[string]struct{}, error) {
		set := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			set[id] = struct{}{}
		}

		return set, nil
	}
}

func evictionIDs(evictions []eviction) []string {
	ids := make([]string, 0, len(evictions))
	for _, e := range evictions {
		ids = append(ids, e.blob.id)
	}

	return ids
}
