package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const (
	peerCount = 4

	ondemandFill = "ondemand"
	prefetchFill = "prefetch"
)

type peer struct {
	*mount.Mounted
}

type peers []peer

func (p peer) metric(t testing.TB, name string) float64 {
	t.Helper()
	v, err := p.writes(name)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return v
}

func (p peer) writes(name string) (float64, error) {
	body, err := p.API.Get("/metrics")
	if err != nil {
		return 0, err
	}

	return mount.ParseMetrics(string(body)).Sum("nydus_cache_write_total", `type="`+name+`"`), nil
}

func (p peer) log() string {
	return p.Daemon.Log() + p.Daemon.FileLog()
}

func (ps peers) sumMetric(t testing.TB, name string) float64 {
	t.Helper()
	var total float64

	for _, p := range ps {
		total += p.metric(t, name)
	}

	return total
}

func (ps peers) sumWrites(name string) (float64, error) {
	var total float64

	for _, p := range ps {
		v, err := p.writes(name)
		if err != nil {
			return 0, err
		}

		total += v
	}

	return total, nil
}

func settled(t testing.TB, sample func() (float64, error)) float64 {
	t.Helper()
	last := -1.0
	if !assert.Eventually(t, func() bool {
		cur, err := sample()
		if err != nil {
			return false
		}

		same := cur > 0 && cur == last
		last = cur

		return same
	}, 60*time.Second, time.Second) {
		t.FailNow()
	}

	return last
}

func (p peer) mustRead(t testing.TB, rel, want string) {
	t.Helper()
	got, err := fstest.HashFileCold(p.Path(rel))
	if !assert.NoError(t, err) || !assert.Equal(t, want, got) {
		t.FailNow()
	}
}

func (p peer) checkRead(t testing.TB, rel, want string) {
	t.Helper()
	got, err := fstest.HashFileCold(p.Path(rel))
	if err != nil {
		t.Logf("read %s failed, which is allowed: %v", rel, err)
		return
	}

	assert.Equal(t, want, got)
}

func (p peer) mustReadAt(t testing.TB, rel string, off int64, n int, data []byte) {
	t.Helper()
	got, err := fstest.ReadAtCold(p.Path(rel), off, int64(n))
	if !assert.NoError(t, err) || !assert.Len(t, got, n) || !assert.Equal(t, data[off:off+int64(n)], got) {
		t.FailNow()
	}
}

func (p peer) judgeLockWait(t *testing.T, rel, want string, release func()) {
	t.Helper()
	done := make(chan readResult, 1)

	go func() {
		var r readResult
		r.sum, r.err = fstest.HashFileCold(p.Path(rel))
		done <- r
	}()

	var r readResult
	blocked := false

	select {
	case r = <-done:

	case <-time.After(lockTimeout):
		blocked = true
	}

	log := p.log()
	release()

	if blocked {
		select {
		case r = <-done:

		case <-time.After(60 * time.Second):
			t.Fatalf("read of %s still blocked a minute after the lock was released", rel)
		}
	}

	if r.err != nil {
		t.Logf("read of %s behind the lock failed, which is allowed: %v", rel, r.err)
	} else {
		assert.Equal(t, want, r.sum)
	}

	p.mustRead(t, rel, want)

	assert.False(t, blocked)
	assert.Regexp(t, lockWord, log)
}

type readResult struct {
	sum string
	err error
}

func readConcurrently(paths []string) []readResult {
	start := make(chan struct{})
	results := make([]readResult, len(paths))
	var wg sync.WaitGroup

	for i, path := range paths {
		wg.Go(func() {
			<-start
			results[i].sum, results[i].err = fstest.HashFileCold(path)
		})
	}

	close(start)
	wg.Wait()

	return results
}

func (ps peers) mustReadConcurrently(t testing.TB, rel, want string) {
	t.Helper()
	paths := make([]string, len(ps))

	for i, p := range ps {
		paths[i] = p.Path(rel)
	}

	for _, r := range readConcurrently(paths) {
		if assert.NoError(t, r.err) {
			assert.Equal(t, want, r.sum)
		}
	}
}
