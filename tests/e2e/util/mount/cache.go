package mount

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The suffixes, after the blob id, of the files the blob cache keeps in a
// cache directory: decoded data, chunk-group map, blob meta and prefetch lock.
const (
	CacheDataSuffix    = ".blob.data"
	CacheMapSuffix     = ".group.map"
	CacheMetaSuffix    = ".blob.meta"
	PrefetchLockSuffix = ".prefetch.lock"
)

// CacheFiles returns the decoded blob data files under dir.
func CacheFiles(dir string) []string {
	files, _ := filepath.Glob(filepath.Join(dir, "*"+CacheDataSuffix))
	return files
}

// Allocated returns the bytes allocated to path, not its apparent size: a
// sparse cache file only grows as ranges are fetched.
func Allocated(path string) int64 {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return 0
	}

	return st.Blocks * 512
}

// CacheUsed sums the allocated bytes of every cache data file under dir.
func CacheUsed(dir string) int64 {
	var total int64

	for _, f := range CacheFiles(dir) {
		total += Allocated(f)
	}

	return total
}
