package cache

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const lockTimeout = 10 * time.Second

var lockWord = regexp.MustCompile(`(?i)\b(f?lock|locked|locks|locking)\b`)

func TestLockWait(t *testing.T) {
	t.Parallel()
	w := setup(t)
	want := w.want["shared.bin"]

	t.Run("StaleMap", func(t *testing.T) {
		t.Parallel()
		cache := newCache(t)
		release := cache.holdFlock(t, w.sharedBlob, mount.CacheMapSuffix)
		m := cache.mount(t, w.lowerImage)
		m.judgeLockWait(t, "shared.bin", want, release)
	})

	t.Run("GroupLock", func(t *testing.T) {
		t.Parallel()
		cache := newCache(t)
		if err := os.MkdirAll(cache.path, 0o755); !assert.NoError(t, err) {
			t.FailNow()
		}
		if err := os.WriteFile(cache.file(w.sharedBlob, mount.CacheDataSuffix), nil, 0o644); !assert.NoError(t, err) {
			t.FailNow()
		}

		release := cache.holdOFD(t, w.sharedBlob, mount.CacheMapSuffix)
		defer release()
		m := cache.mount(t, w.lowerImage)

		const page = 4096

		readGroup := func(off int64) <-chan readResult {
			done := make(chan readResult, 1)

			go func() {
				data, err := fstest.ReadAtCold(m.Path("shared.bin"), off, page)
				done <- readResult{sum: sha256Hex(data), err: err}
			}()

			return done
		}

		check := func(r readResult, off int) {
			t.Helper()
			if !assert.NoError(t, r.err) {
				t.FailNow()
			}
			if want := sha256Hex(w.data["shared.bin"][off : off+page]); !assert.Equal(t, want, r.sum) {
				t.FailNow()
			}
		}

		select {
		case r := <-readGroup(0):
			check(r, 0)

		case <-time.After(lockTimeout):
			t.Fatalf("one fetch window blocked over %s on a group lock", lockTimeout)
		}

		assert.Regexp(t, lockWord, m.log())

		off := len(w.data["shared.bin"]) - page
		done := readGroup(int64(off))

		select {
		case r := <-done:
			check(r, off)
			t.Fatal("a later cold fetch bypassed the peer's group lock after a timeout")

		case <-time.After(200 * time.Millisecond):
		}

		release()

		select {
		case r := <-done:
			check(r, off)

		case <-time.After(lockTimeout):
			t.Fatalf("read still blocked %s after the group lock was released", lockTimeout)
		}

		m.mustRead(t, "shared.bin", want)
	})

	t.Run("PrefetchLock", func(t *testing.T) {
		t.Parallel()
		cache := newCache(t)
		var releases []func()

		for _, key := range []string{w.lowerBlob, w.sharedBlob} {
			releases = append(releases, cache.holdFlock(t, key, mount.PrefetchLockSuffix))
		}

		start := time.Now()
		m := cache.mount(t, w.lowerImage, prefetchAll)

		m.Daemon.WaitFor(t, lockTimeout, "the prefetch lock wait to be logged", func() bool {
			return strings.Contains(m.log(), "is held by another process (waiting)")
		})

		m.mustRead(t, "shared.bin", want)

		assert.Eventually(t, func() bool {
			v, err := m.writes(prefetchFill)
			return (err == nil && v > 0) || strings.Contains(m.log(), "without cross-process lock")
		}, max(time.Until(start.Add(lockTimeout)), 2*time.Second), 200*time.Millisecond)

		for _, release := range releases {
			release()
		}

		cache.waitAllReady(t, w.lowerBlob)
		assert.NotZero(t, m.metric(t, prefetchFill))
		fstest.VerifyMount(t, m.Root, w.lowerImage.Want, w.lowerImage.Compare())
	})
}
