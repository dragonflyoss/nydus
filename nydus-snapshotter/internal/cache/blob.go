/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// blobDataSuffix names a blob's sparse decoded data.
	blobDataSuffix = ".blob.data"

	// blobMetaSuffix names a blob's chunk table.
	blobMetaSuffix = ".blob.meta"

	// groupMapSuffix names a blob's chunk group bitmap.
	groupMapSuffix = ".group.map"

	// prefetchLockSuffix names the lock a daemon holds while prefetching a
	// blob.
	prefetchLockSuffix = ".prefetch.lock"

	// blockSize is the unit of stat's block count.
	blockSize = 512
)

// blobSuffixes are the cache files of one blob, refer to the Bootstrap plus
// blob-dir mount section of docs/nydus.md.
var blobSuffixes = []string{blobDataSuffix, blobMetaSuffix, groupMapSuffix, prefetchLockSuffix}

// blob is one blob's cache files.
type blob struct {
	// id is the blob ID.
	id string

	// files are the blob's cache files.
	files []string

	// size is the disk space evicting the files frees.
	size uint64

	// modTime is the latest file modification.
	modTime time.Time

	// accessTime is when a daemon referencing the blob last started or stopped.
	accessTime time.Time
}

// add adds a cache file to the blob. Its allocated blocks count, since data
// files are sparse; a file linked elsewhere, a blob meta shared with its
// bootstrap layer, frees nothing.
func (b *blob) add(path string, info os.FileInfo) {
	b.files = append(b.files, path)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Nlink <= 1 {
			b.size += uint64(stat.Blocks) * blockSize
		}
	} else {
		b.size += uint64(info.Size())
	}

	if info.ModTime().After(b.modTime) {
		b.modTime = info.ModTime()
	}
}

// lockPrefetch takes the blob's prefetch lock without blocking, so no daemon
// prefetches it while it is evicted. It reports false when a daemon holds the
// lock; an absent lock file is free.
func (b *blob) lockPrefetch(dir string) (func(), bool, error) {
	f, err := os.Open(filepath.Join(dir, b.id+prefetchLockSuffix))
	if errors.Is(err, os.ErrNotExist) {
		return func() {}, true, nil
	}

	if err != nil {
		return nil, false, err
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, false, nil
		}

		return nil, false, err
	}

	return func() { f.Close() }, true, nil
}

// blobID returns the blob ID of a cache file name.
func blobID(name string) (string, bool) {
	for _, suffix := range blobSuffixes {
		if id, ok := strings.CutSuffix(name, suffix); ok && id != "" {
			return id, true
		}
	}

	return "", false
}
