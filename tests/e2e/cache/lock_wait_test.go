package cache

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// lockBound is how long a daemon may wait on a cache lock another process
// holds before it must have moved on.
const lockBound = 10 * time.Second

// lockWord finds a log line about a lock (but not a "block").
var lockWord = regexp.MustCompile(`(?i)\b(f?lock|locked|locks|locking)\b`)

// TestLockWait has another process hold each lock daemons take on a shared
// cache, as a hung or stopped peer would. Reads must stay correct and go
// through once the lock is released; the wait itself must be bounded and
// reported, which only the prefetch lock currently is.
func TestLockWait(t *testing.T) {
	t.Parallel()
	w := setup(t)
	want := w.want["shared.bin"]

	// A group map without its data file is stale: opening the cache resets
	// it under flock(LOCK_EX), with no timeout.
	t.Run("stale-map", func(t *testing.T) {
		t.Parallel()
		cacheDir := newCache(t)
		release := holdFlock(t, cacheFile(cacheDir, w.keyB, mapSuffix))
		m := mountOn(t, w.image1, cacheDir)
		judgeLockWait(t, m, "shared.bin", want, release)
	})

	// A fetch claims its groups with an OFD lock on their bytes of the group
	// map (F_OFD_SETLKW, no timeout). Both cache files exist, so the cache
	// is not stale and the read goes straight to the claim.
	t.Run("group-lock", func(t *testing.T) {
		t.Parallel()
		cacheDir := newCache(t)
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			t.Fatalf("create cache: %v", err)
		}
		if err := os.WriteFile(cacheFile(cacheDir, w.keyB, dataSuffix), nil, 0o644); err != nil {
			t.Fatalf("create cache data: %v", err)
		}
		release := holdOFD(t, cacheFile(cacheDir, w.keyB, mapSuffix))
		m := mountOn(t, w.image1, cacheDir)
		judgeLockWait(t, m, "shared.bin", want, release)
	})

	// Prefetch takes a per-blob flock, polling while a peer holds it.
	t.Run("prefetch-lock", func(t *testing.T) {
		t.Parallel()
		cacheDir := newCache(t)
		var releases []func()
		for _, key := range []string{w.keyA, w.keyB} {
			releases = append(releases, holdFlock(t, cacheFile(cacheDir, key, prefetchSuffix)))
		}
		start := time.Now()
		m := mountOn(t, w.image1, cacheDir, prefetchAll)

		m.Daemon.WaitFor(t, lockBound, "the prefetch lock wait to be logged", func() bool {
			return strings.Contains(daemonLog(m), "is held by another process (waiting)")
		})
		// On-demand fills take no prefetch lock.
		mustRead(t, m.Path("shared.bin"), want)

		// file1.bin stays unread, so blob A's prefetch has nothing to stop
		// waiting for but the lock.
		bounded := false
		for time.Since(start) < lockBound {
			if metric(t, m, prefetchFill) > 0 || strings.Contains(daemonLog(m), "without cross-process lock") {
				bounded = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}

		for _, release := range releases {
			release()
		}
		// With the holder gone the prefetch takes the lock over.
		waitAllReady(t, cacheDir, w.keyA)
		if metric(t, m, prefetchFill) == 0 {
			t.Errorf("blob A became ready without a prefetch fill")
		}
		oracle.VerifyMount(t, m.Root, w.image1.Want, w.image1.Compare())

		if !bounded {
			t.Errorf("prefetch still waiting on another process's lock after %s", lockBound)
		}
	})
}

// judgeLockWait reads rel from m while release still holds a cache lock. The
// read must end with the right bytes, or fail, and a read after the release
// must succeed. Whether the wait was bounded and logged is judged last,
// under KI-4, because a reproduced known issue ends the test.
func judgeLockWait(t *testing.T, m *mount.Mounted, rel, want string, release func()) {
	t.Helper()
	done := make(chan readResult, 1)
	go func() {
		var r readResult
		r.sum, r.err = readSum(m.Path(rel))
		done <- r
	}()
	var r readResult
	blocked := false
	select {
	case r = <-done:
	case <-time.After(lockBound):
		blocked = true
	}
	log := daemonLog(m)
	release()
	if blocked {
		select {
		case r = <-done:
		case <-time.After(60 * time.Second):
			t.Fatalf("read of %s still blocked a minute after the lock was released", rel)
		}
	}
	switch {
	case r.err != nil:
		t.Logf("read of %s behind the lock failed, which is allowed: %v", rel, r.err)
	case r.sum != want:
		t.Errorf("read of %s behind the lock returned wrong bytes: sha256 %s, want %s", rel, r.sum, want)
	}
	mustRead(t, m.Path(rel), want)

	if blocked {
		t.Errorf("read of %s blocked over %s on a lock another process holds", rel, lockBound)
	}
	if !lockWord.MatchString(log) {
		t.Errorf("daemon did not log the lock it waited on")
	}
}

// daemonLog is everything m's daemon logged, console and file sinks.
func daemonLog(m *mount.Mounted) string {
	return m.Daemon.Log() + m.Daemon.FileLog()
}
