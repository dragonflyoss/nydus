//go:build manual

package bench

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/proc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type modeResult struct {
	mountSec          float64
	coldWalkSec       float64
	coldWalkEntries   int
	coldXattrWalkSec  float64
	negativeLookupOps float64
	bigDirLookupOps   float64
	firstReadSec      float64
	coldSeqMiBps      float64
	coldSeqCachedMiB  float64
	fetchedMiB        float64
	coldRandIOPS      float64
	coldRandLatUs     float64
	warm              map[string]*fioResult
}

func (m *mode) runMode(t testing.TB, fio string, warm bool, smallFiles int) *modeResult {
	t.Helper()
	dropCaches(t)
	res := &modeResult{fetchedMiB: -1}

	func() {
		mountStart := time.Now()
		s := m.start(t)
		defer s.stop()
		res.mountSec = time.Since(mountStart).Seconds()
		t.Logf("  mount ready: %.2fs", res.mountSec)

		res.coldWalkSec, res.coldWalkEntries = s.coldMetadataWalk(t, false)

		t.Logf("  cold metadata walk: %d entries in %.3fs (%.0f entries/s)",
			res.coldWalkEntries, res.coldWalkSec, float64(res.coldWalkEntries)/res.coldWalkSec)

		res.negativeLookupOps = s.negativeLookup(t, statRel)
		t.Logf("  negative lookups: %.0f ops/s", res.negativeLookupOps)

		dropCaches(t)
		target := filepath.Join(s.root, targetRel)
		readStart := time.Now()
		_, err := fstest.ReadAt(target, 0, 1<<20)
		assert.NoError(t, err)
		res.firstReadSec = time.Since(readStart).Seconds()
		t.Logf("  first 1MiB cold read: %.3fs", res.firstReadSec)

		cachedBefore := cachedMiB(t)
		seqStart := time.Now()
		n := readWhole(t, target)
		res.coldSeqMiBps = float64(n) / (1 << 20) / time.Since(seqStart).Seconds()
		res.coldSeqCachedMiB = cachedMiB(t) - cachedBefore

		t.Logf("  cold seq read: %.1f MiB at %.1f MiB/s, page cache +%.1f MiB",
			float64(n)/(1<<20), res.coldSeqMiBps, res.coldSeqCachedMiB)

		if fetched := s.backendReadMiB(); fetched >= 0 {
			res.fetchedMiB = fetched
			t.Logf("  backend bytes for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), res.fetchedMiB)
		} else if s.cache != "" {
			res.fetchedMiB = float64(mount.CacheUsed(s.cache)) / (1 << 20)
			t.Logf("  cache allocation for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), res.fetchedMiB)
		}

		dropCaches(t)
		res.coldRandIOPS, res.coldRandLatUs = coldRandRead(t, fio, filepath.Join(s.root, randRel))
		t.Logf("  cold rand read 4K: %.0f IOPS, %.0f µs", res.coldRandIOPS, res.coldRandLatUs)

		if warm {
			statDir := filepath.Join(s.root, statRel)
			res.warm = runWarmBenchmarks(t, fio, target, statDir, filepath.Join(s.root, readdirRel))
			dropCaches(t)
			addMetaBenchmarks(t, res.warm, filepath.Join(s.root, xattrRel), xattrName, statDir)
		}
	}()

	dropCaches(t)

	func() {
		s := m.start(t)
		defer s.stop()
		res.coldXattrWalkSec, _ = s.coldMetadataWalk(t, true)

		t.Logf("  cold walk + xattr: %.3fs (xattr delta %+.3fs)",
			res.coldXattrWalkSec, res.coldXattrWalkSec-res.coldWalkSec)
	}()

	dropCaches(t)

	func() {
		s := m.start(t)
		defer s.stop()
		start := time.Now()

		for i := smallFiles - 1; i >= 0; i-- {
			_, err := os.Lstat(filepath.Join(s.root, statRel, fmt.Sprintf("file_%04d.txt", i)))
			assert.NoError(t, err)
		}

		res.bigDirLookupOps = float64(smallFiles) / time.Since(start).Seconds()
		t.Logf("  big directory cold positive lookup: %d entries, %.0f ops/s", smallFiles, res.bigDirLookupOps)
	}()

	return res
}

func (s *served) coldMetadataWalk(t testing.TB, withXattr bool) (float64, int) {
	root := s.root
	t.Helper()
	entries := 0
	buf := make([]byte, 4096)
	start := time.Now()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if _, err := d.Info(); err != nil {
			return err
		}

		if withXattr {
			_, _ = unix.Llistxattr(path, buf)
		}

		entries++

		return nil
	})

	elapsed := time.Since(start).Seconds()

	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NotZero(t, entries) {
		t.FailNow()
	}

	return elapsed, entries
}

func (s *served) negativeLookup(t testing.TB, rel string) float64 {
	dir := filepath.Join(s.root, rel)
	t.Helper()
	names := make([]string, 64)
	for i := range names {
		names[i] = filepath.Join(dir, fmt.Sprintf("no_such_module_%d.js", i))
	}

	ops := 0
	start := time.Now()

	deadline := start.Add(time.Second)
	for time.Now().Before(deadline) {
		for _, name := range names {
			_, err := os.Lstat(name)
			assert.ErrorIs(t, err, os.ErrNotExist)
		}

		ops += len(names)
	}

	return float64(ops) / time.Since(start).Seconds()
}

func (s *served) backendReadMiB() float64 {
	if s.api == nil {
		return -1
	}

	body, err := s.api.Get("/metrics")
	if err != nil {
		return -1
	}

	m := mount.ParseMetrics(string(body))

	return (m.Sum("nydus_backend_read_bytes_total", `type="ondemand"`) + m.Sum("nydus_backend_read_bytes_total", `type="prefetch"`)) / (1 << 20)
}

func cachedMiB(t testing.TB) float64 {
	t.Helper()
	info, err := proc.Status("/proc/meminfo")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	kb, err := strconv.ParseFloat(strings.TrimSuffix(info["Cached"], " kB"), 64)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return kb / 1024
}

func dropCaches(t testing.TB) {
	t.Helper()
	unix.Sync()
	assert.NoError(t, os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o644))
}

func readWhole(t testing.TB, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	n, err := io.Copy(io.Discard, f)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return n
}
