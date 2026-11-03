package fault

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type readers struct {
	stop      chan struct{}
	stopOnce  sync.Once
	done      chan struct{}
	ok        atomic.Int64
	fails     atomic.Int64
	mu        sync.Mutex
	wrong     []string
	firstErrs []string
}

func (r *readers) halt() { r.stopOnce.Do(func() { close(r.stop) }) }

func (r *readers) note(list *[]string, s string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(*list) < 8 {
		*list = append(*list, s)
	}
}

func (r *readers) waitOK(t testing.TB, n int64, timeout time.Duration) {
	t.Helper()
	if !assert.Eventually(t, func() bool { return r.ok.Load() >= n }, timeout, 20*time.Millisecond) {
		t.FailNow()
	}
}

func (r *readers) stopWithin(t testing.TB, timeout time.Duration) {
	t.Helper()
	r.halt()

	select {
	case <-r.done:

	case <-time.After(timeout):
		t.Fatalf("a reader is still blocked %s after stop: reads hang", timeout)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Empty(t, r.wrong)
	t.Logf("readers: %d ok, %d failed; first errors: %v", r.ok.Load(), r.fails.Load(), r.firstErrs)
}
