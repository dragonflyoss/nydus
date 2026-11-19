/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	storemocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store/mocks"
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

func TestGC_collect(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]time.Time
		touched   map[string]time.Time
		running   []string
		committed []string
		canceled  bool
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
			name:  "evict more orphans than a batch holds",
			files: mockOrphanFiles(evictBatchSize + 1),
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				entries, err := os.ReadDir(dir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:     "stop a round whose context is done",
			files:    map[string]time.Time{"a.blob.data": mockOld},
			canceled: true,
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
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
			name:      "keep blob with a future access time",
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
		{
			name:  "ignore a file that is no blob",
			files: map[string]time.Time{"notes.txt": mockOld},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "notes.txt"))
			},
		},
		{
			name:  "running blobs cannot be told",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				g.running = blobsError(errors.New("foo"))
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "committed blobs cannot be told",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				g.committed = blobsError(errors.New("foo"))
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "running blobs cannot be told once the candidates are picked",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				calls := 0
				g.running = func(context.Context) (map[string]struct{}, error) {
					calls++
					if calls == 1 {
						return map[string]struct{}{}, nil
					}

					return nil, errors.New("foo")
				}
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "running blobs take too long to tell once the candidates are picked",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				calls := 0
				g.running = func(ctx context.Context) (map[string]struct{}, error) {
					calls++
					if calls == 1 {
						return map[string]struct{}{}, nil
					}

					<-ctx.Done()
					return nil, ctx.Err()
				}
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.DeadlineExceeded)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "cache dir cannot be read",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				g.dir = filepath.Join(g.dir, "missing")
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "blob access times cannot be read",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				m := storemocks.NewMockStore(gomock.NewController(t))
				m.EXPECT().ListBlobs().Return(nil, errors.New("foo")).Times(1)
				g.store = m
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "disk usage cannot be told",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				g.statfs = func(string, *unix.Statfs_t) error { return errors.New("foo") }
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "statfs "+dir+": foo")
				assert.FileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:  "evict a blob whose access time cannot be forgotten",
			files: map[string]time.Time{"a.blob.data": mockOld},
			prepare: func(t *testing.T, g *gc) {
				m := storemocks.NewMockStore(gomock.NewController(t))
				gomock.InOrder(
					m.EXPECT().ListBlobs().Return(map[string]time.Time{}, nil).Times(1),
					m.EXPECT().DeleteBlobs([]string{"a"}).Return(errors.New("foo")).Times(1),
				)
				g.store = m
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(dir, "a.blob.data"))
			},
		},
		{
			name:    "keep an orphan whose file cannot be removed and remember it",
			touched: map[string]time.Time{"a": mockOld},
			prepare: func(t *testing.T, g *gc) {
				mockUnremovable(t, filepath.Join(g.dir, "a.blob.data"))
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(dir, "a.blob.data"))
				blobs, err := s.ListBlobs()
				assert.NoError(err)
				assert.Contains(blobs, "a")
			},
		},
		{
			name: "keep a stale temporary file that cannot be removed",
			prepare: func(t *testing.T, g *gc) {
				mockUnremovable(t, filepath.Join(g.dir, ".blob-meta-123.tmp"))
			},
			expect: func(t *testing.T, dir string, s store.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(dir, ".blob-meta-123.tmp"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
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

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if tc.canceled {
					cancel()
				}

				start := time.Now()
				err := g.collect(ctx)
				assert.LessOrEqual(t, time.Since(start), recheckTimeout)
				tc.expect(t, dir, s, err)
			})
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
				assert.False(g.evict(t.Context(), b, metrics.ReasonOrphan))
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
				assert.True(g.evict(t.Context(), b, metrics.ReasonOrphan))
				assert.NoFileExists(lock)
			},
		},
		{
			name: "evict blob without a prefetch lock",
			expect: func(t *testing.T, g *gc, dir string) {
				assert := assert.New(t)
				data := filepath.Join(dir, "a.blob.data")
				assert.NoError(os.WriteFile(data, nil, 0o644))

				b := &blob{id: "a", files: []string{data, filepath.Join(dir, "a.blob.meta")}}
				assert.True(g.evict(t.Context(), b, metrics.ReasonOrphan))
				assert.NoFileExists(data)
			},
		},
		{
			name: "keep blob whose prefetch lock cannot be opened",
			expect: func(t *testing.T, g *gc, dir string) {
				assert := assert.New(t)
				data := filepath.Join(dir, "a.blob.data")
				assert.NoError(os.WriteFile(data, nil, 0o644))
				g.dir = data

				b := &blob{id: "a", files: []string{data}}
				assert.False(g.evict(t.Context(), b, metrics.ReasonOrphan))
				assert.FileExists(data)
			},
		},
		{
			name: "keep blob whose file cannot be removed",
			expect: func(t *testing.T, g *gc, dir string) {
				assert := assert.New(t)
				data := filepath.Join(dir, "a.blob.data")
				mockUnremovable(t, data)

				b := &blob{id: "a", files: []string{data}}
				assert.False(g.evict(t.Context(), b, metrics.ReasonOrphan))
				assert.DirExists(data)
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

func TestGC_watermarkCandidates(t *testing.T) {
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
			picked: []eviction{{blob: &blob{id: "orphan", size: 30}, reason: metrics.ReasonOrphan}},
			lru:    []*blob{{id: "a", size: 20, accessTime: mockOld}},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(evictions)
			},
		},
		{
			name:  "skip a blob that frees nothing",
			usage: diskUsage{total: 100, used: 90},
			lru: []*blob{
				{id: "linked", accessTime: mockNow.Add(-3 * time.Hour)},
				{id: "a", size: 40, accessTime: mockOld},
			},
			expect: func(t *testing.T, evictions []eviction, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"a"}, evictionIDs(evictions))
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
			evictions, err := g.watermarkCandidates(t.Context(), tc.cached, tc.picked, tc.lru)
			tc.expect(t, evictions, err)
		})
	}
}

func TestGC_Run(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, g *gc, blob string, failing *atomic.Bool)
	}{
		{
			name: "run a round every interval",
			expect: func(t *testing.T, g *gc, blob string, failing *atomic.Bool) {
				assert := assert.New(t)
				time.Sleep(time.Duration(g.cfg.Interval) - time.Second)
				synctest.Wait()
				assert.FileExists(blob)

				time.Sleep(time.Second)
				synctest.Wait()
				assert.NoFileExists(blob)

				mockBlobFile(t, blob)
				time.Sleep(time.Duration(g.cfg.Interval))
				synctest.Wait()
				assert.NoFileExists(blob)
			},
		},
		{
			name: "retry a round a starting daemon skipped after the busy interval",
			expect: func(t *testing.T, g *gc, blob string, failing *atomic.Bool) {
				assert := assert.New(t)
				lock := g.StartLock()
				lock.Lock()
				time.Sleep(time.Duration(g.cfg.Interval))
				synctest.Wait()
				assert.FileExists(blob)

				lock.Unlock()
				time.Sleep(busyRetryInterval)
				synctest.Wait()
				assert.NoFileExists(blob)
			},
		},
		{
			name: "keep running after a round that fails",
			expect: func(t *testing.T, g *gc, blob string, failing *atomic.Bool) {
				assert := assert.New(t)
				failing.Store(true)
				time.Sleep(time.Duration(g.cfg.Interval))
				synctest.Wait()
				assert.FileExists(blob)

				failing.Store(false)
				time.Sleep(time.Duration(g.cfg.Interval))
				synctest.Wait()
				assert.NoFileExists(blob)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := config.New()
				cfg.RootDir = t.TempDir()
				cfg.GC = mockGCConfig
				assert.NoError(t, os.Mkdir(cfg.CacheDir(), 0o700))
				blob := filepath.Join(cfg.CacheDir(), "a.blob.data")
				mockBlobFile(t, blob)

				failing := &atomic.Bool{}
				running := func(context.Context) (map[string]struct{}, error) {
					if failing.Load() {
						return nil, errors.New("foo")
					}

					return map[string]struct{}{}, nil
				}

				g := New(cfg, newTestStore(t), running, blobSet(nil)).(*gc)
				g.now = func() time.Time { return mockNow }
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					defer close(done)
					g.Run(ctx)
				}()

				tc.expect(t, g, blob, failing)
				cancel()
				<-done
			})
		})
	}
}

func TestGC_usage(t *testing.T) {
	tests := []struct {
		name      string
		threshold config.Size
		dir       func(t *testing.T) string
		expect    func(t *testing.T, usage diskUsage, err error)
	}{
		{
			name: "usage of the file system holding the cache",
			dir:  func(t *testing.T) string { return t.TempDir() },
			expect: func(t *testing.T, usage diskUsage, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotZero(usage.total)
				assert.LessOrEqual(usage.used, usage.total)
			},
		},
		{
			name:      "cached bytes against the disk threshold",
			threshold: 100,
			dir:       func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			expect: func(t *testing.T, usage diskUsage, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(diskUsage{total: 100, used: 40}, usage)
			},
		},
		{
			name: "missing cache dir",
			dir:  func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			expect: func(t *testing.T, usage diskUsage, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Zero(usage)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGC(tc.dir(t), nil, diskUsage{})
			g.cfg.Policy.DiskThreshold = tc.threshold
			g.statfs = unix.Statfs
			usage, err := g.usage(40)
			tc.expect(t, usage, err)
		})
	}
}

func mockBlobFile(t *testing.T, path string) {
	t.Helper()
	assert.NoError(t, os.WriteFile(path, []byte("data"), 0o644))
	assert.NoError(t, os.Chtimes(path, mockOld, mockOld))
}

func mockUnremovable(t *testing.T, path string) {
	t.Helper()
	assert.NoError(t, os.MkdirAll(filepath.Join(path, "child"), 0o755))
	assert.NoError(t, os.Chtimes(path, mockOld, mockOld))
}

func blobsError(err error) BlobsFunc {
	return func(context.Context) (map[string]struct{}, error) {
		return nil, err
	}
}

func mockOrphanFiles(n int) map[string]time.Time {
	files := make(map[string]time.Time, n)
	for i := range n {
		files[fmt.Sprintf("%02d.blob.data", i)] = mockOld
	}

	return files
}

func newTestGC(dir string, s store.Store, usage diskUsage) *gc {
	return &gc{
		cfg:   mockGCConfig,
		dir:   dir,
		store: s,
		now:   func() time.Time { return mockNow },
		statfs: func(_ string, stat *unix.Statfs_t) error {
			*stat = unix.Statfs_t{Bsize: 1, Blocks: usage.total, Bavail: usage.total - usage.used}
			return nil
		},
	}
}

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "nydusd.db"), store.DefaultOpenTimeout)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

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
