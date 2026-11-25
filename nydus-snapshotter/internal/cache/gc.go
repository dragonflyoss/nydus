/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cache garbage collects the blob cache shared by nydus daemons, by
// TTL and disk watermarks.
package cache

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/containerd/log"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

const (
	// recentWindow protects files written lately, which a starting daemon or
	// a racing pull may be about to use.
	recentWindow = 5 * time.Minute

	// busyRetryInterval is when a round skipped by a starting daemon retries.
	busyRetryInterval = 5 * time.Second

	// evictBatchSize is how many blobs a round unlinks under the lock at
	// once, so a starting daemon waits for one batch at most, never for a
	// whole round.
	evictBatchSize = 16

	// recheckTimeout bounds asking for the running blobs under the lock, so a
	// starting daemon never waits for a hung answer either.
	recheckTimeout = 5 * time.Second
)

// errBusy means a daemon is starting and the round must retry.
var errBusy = errors.New("cache is in use by a starting daemon")

// BlobsFunc returns a set of blob IDs.
type BlobsFunc func(ctx context.Context) (map[string]struct{}, error)

// GC evicts blobs from the shared cache.
type GC interface {
	// Run runs a round every interval until ctx is done.
	Run(ctx context.Context)

	// DaemonStartLock returns the lock a starting daemon holds, so no round
	// evicts a blob the daemon is about to use.
	DaemonStartLock() sync.Locker
}

// diskUsage is the size and usage of a filesystem in bytes.
type diskUsage struct {
	// total is the filesystem size.
	total uint64

	// used is the space in use.
	used uint64
}

// eviction is a blob to evict and why.
type eviction struct {
	// blob is the blob.
	blob *blob

	// reason is the eviction reason label.
	reason string
}

// gc is the blob cache GC.
type gc struct {
	// cfg is the GC config.
	cfg config.GCConfig

	// dir is the cache directory.
	dir string

	// store holds blob access times.
	store store.Store

	// running returns the blobs running daemons reference.
	running BlobsFunc

	// committed returns the blobs committed bootstraps reference.
	committed BlobsFunc

	// now returns the current time.
	now func() time.Time

	// statfs is statfs(2).
	statfs func(path string, stat *unix.Statfs_t) error

	// mu is held for reading by starting daemons; a round takes it for
	// writing only to recheck and unlink a batch, or is skipped.
	mu sync.RWMutex
}

// New returns the GC of the blob cache of cfg. running and committed tell
// the blobs that daemons and committed bootstraps reference.
func New(cfg *config.Config, s store.Store, running, committed BlobsFunc) GC {
	return &gc{
		cfg:       cfg.GC,
		dir:       cfg.CacheDir(),
		store:     s,
		running:   running,
		committed: committed,
		now:       time.Now,
		statfs:    unix.Statfs,
	}
}

// DaemonStartLock returns the lock a starting daemon holds, so no round
// evicts a blob the daemon is about to use.
func (g *gc) DaemonStartLock() sync.Locker {
	return g.mu.RLocker()
}

// Run runs a round every interval until ctx is done.
func (g *gc) Run(ctx context.Context) {
	timer := time.NewTimer(time.Duration(g.cfg.Interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		// Bound a round by the interval.
		next := time.Duration(g.cfg.Interval)
		roundCtx, cancel := context.WithTimeout(ctx, next)
		if err := g.collect(roundCtx); errors.Is(err, errBusy) {
			next = busyRetryInterval
		} else if err != nil && ctx.Err() == nil {
			log.G(ctx).WithError(err).Error("cache gc")
		}
		cancel()

		timer.Reset(next)
	}
}

// collect runs one round: pick candidates without the lock, then recheck them
// against the running daemons and unlink them under it, a batch at a time.
func (g *gc) collect(ctx context.Context) error {
	evictions, err := g.candidates(ctx)
	if err != nil {
		return err
	}

	var evictErr error
	evicted := make([]string, 0, len(evictions))
	for batch := range slices.Chunk(evictions, evictBatchSize) {
		ids, err := g.evictBatch(ctx, batch)
		if err != nil {
			evictErr = err
			break
		}

		evicted = append(evicted, ids...)
	}

	// Forget the evicted blobs in one transaction.
	if len(evicted) > 0 {
		if err := g.store.DeleteBlobs(evicted); err != nil {
			log.G(ctx).WithError(err).Warn("forget evicted blobs")
		}
	}

	return evictErr
}

// evictBatch rechecks a batch of candidates against the running daemons and
// unlinks them under the lock, and returns the blobs it evicted. It fails
// with errBusy while a daemon starts and once ctx is done.
func (g *gc) evictBatch(ctx context.Context, batch []eviction) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !g.mu.TryLock() {
		return nil, errBusy
	}
	defer g.mu.Unlock()

	// A daemon may have started since the candidates were picked.
	recheckCtx, cancel := context.WithTimeout(ctx, recheckTimeout)
	running, err := g.running(recheckCtx)
	cancel()
	if err != nil {
		return nil, err
	}

	evicted := make([]string, 0, len(batch))
	for _, e := range batch {
		if _, ok := running[e.blob.id]; !ok && g.evict(ctx, e.blob, e.reason) {
			evicted = append(evicted, e.blob.id)
		}
	}

	return evicted, nil
}

// candidates returns the blobs to evict: orphans, blobs past their TTL, and
// least recently used blobs over the high watermark. Blobs of running
// daemons and recent writes are never candidates.
func (g *gc) candidates(ctx context.Context) ([]eviction, error) {
	running, err := g.running(ctx)
	if err != nil {
		return nil, err
	}

	committed, err := g.committed(ctx)
	if err != nil {
		return nil, err
	}

	blobs, err := g.scan(ctx)
	if err != nil {
		return nil, err
	}

	now := g.now()
	var (
		evictions []eviction
		lru       []*blob
		cached    uint64
	)
	for _, b := range blobs {
		cached += b.size
		if _, ok := running[b.id]; ok || now.Sub(b.modTime) < recentWindow {
			continue
		}

		_, referenced := committed[b.id]
		switch {
		case !referenced:
			evictions = append(evictions, eviction{blob: b, reason: metrics.ReasonOrphan})
		case now.Sub(b.accessTime) > time.Duration(g.cfg.Policy.BlobTTL):
			evictions = append(evictions, eviction{blob: b, reason: metrics.ReasonTTL})
		default:
			lru = append(lru, b)
		}
	}

	watermark, err := g.watermarkCandidates(ctx, cached, evictions, lru)
	if err != nil {
		return nil, err
	}

	return append(evictions, watermark...), nil
}

// watermarkCandidates returns the least recently used blobs to evict once
// usage reaches the high watermark, down to the low watermark. The blobs
// already picked count as freed. Without disk_threshold, a disk others fill
// can evict every unused blob each round; disk_threshold bounds the cache by
// its own bytes instead.
func (g *gc) watermarkCandidates(ctx context.Context, cached uint64, picked []eviction, lru []*blob) ([]eviction, error) {
	usage, err := g.usage(cached)
	if err != nil {
		return nil, err
	}

	if usage.total == 0 || usage.used*100 < usage.total*uint64(g.cfg.Policy.DiskHighThresholdPercent) {
		return nil, nil
	}

	need := usage.used - min(usage.used, usage.total*uint64(g.cfg.Policy.DiskLowThresholdPercent)/100)
	for _, e := range picked {
		need -= min(need, e.blob.size)
	}

	log.G(ctx).WithFields(log.Fields{"used": usage.used, "total": usage.total, "need": need}).Info("cache usage is over the high watermark")
	slices.SortFunc(lru, func(a, b *blob) int {
		return a.accessTime.Compare(b.accessTime)
	})

	var evictions []eviction
	for _, b := range lru {
		if need == 0 {
			break
		}

		// A blob whose files are all linked elsewhere frees nothing.
		if b.size == 0 {
			continue
		}

		evictions = append(evictions, eviction{blob: b, reason: metrics.ReasonWatermark})
		need -= min(need, b.size)
	}

	return evictions, nil
}

// evict removes a blob's cache files and reports whether it did. A blob whose
// prefetch lock is held is in use and kept.
func (g *gc) evict(ctx context.Context, b *blob, reason string) bool {
	logger := log.G(ctx).WithFields(log.Fields{"blob": b.id, "reason": reason})
	unlock, locked, err := b.lockPrefetch(g.dir)
	if err != nil {
		logger.WithError(err).Warn("lock blob prefetch")
		return false
	}

	if !locked {
		return false
	}
	defer unlock()

	for _, file := range b.files {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.WithError(err).Warn("evict blob")
			return false
		}
	}

	metrics.CacheEvictedBytesTotal.WithLabelValues(reason).Add(float64(b.size))
	logger.WithField("bytes", b.size).Info("evicted blob")

	return true
}

// usage returns the usage the watermarks apply to. With disk_threshold, it
// is the cache's own bytes against the threshold, a logical quota. Without,
// it is the usage of the cache's filesystem.
func (g *gc) usage(cached uint64) (diskUsage, error) {
	if g.cfg.Policy.DiskThreshold > 0 {
		return diskUsage{total: uint64(g.cfg.Policy.DiskThreshold), used: cached}, nil
	}

	var stat unix.Statfs_t
	if err := g.statfs(g.dir, &stat); err != nil {
		return diskUsage{}, fmt.Errorf("statfs %s: %w", g.dir, err)
	}

	total := stat.Blocks * uint64(stat.Bsize)
	return diskUsage{total: total, used: total - stat.Bavail*uint64(stat.Bsize)}, nil
}

// scan groups the cache files by blob and removes stale temporary files.
func (g *gc) scan(ctx context.Context) ([]*blob, error) {
	entries, err := os.ReadDir(g.dir)
	if err != nil {
		return nil, fmt.Errorf("read cache dir %s: %w", g.dir, err)
	}

	times, err := g.store.ListBlobs()
	if err != nil {
		return nil, err
	}

	now := g.now()
	blobs := map[string]*blob{}
	for _, entry := range entries {
		path := filepath.Join(g.dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if strings.HasPrefix(entry.Name(), TempMetaPrefix) {
			g.removeStaleTempFile(ctx, path, now.Sub(info.ModTime()))
			continue
		}

		id, ok := cacheFile(entry.Name()).blobID()
		if !ok {
			continue
		}

		b, ok := blobs[id]
		if !ok {
			b = &blob{id: id}
			blobs[id] = b
		}
		b.add(path, info)
	}

	result := make([]*blob, 0, len(blobs))
	for _, b := range blobs {
		// A blob without a recorded access predates the store; its files tell.
		b.accessTime = b.modTime
		if t, ok := times[b.id]; ok {
			b.accessTime = t
		}

		result = append(result, b)
	}

	slices.SortFunc(result, func(a, b *blob) int {
		return cmp.Compare(a.id, b.id)
	})

	return result, nil
}

// removeStaleTempFile removes a temporary file of the given age once no write
// can still be using it.
func (g *gc) removeStaleTempFile(ctx context.Context, path string, age time.Duration) {
	if age <= recentWindow {
		return
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.G(ctx).WithError(err).WithField("path", path).Warn("remove stale temporary file")
	}
}
