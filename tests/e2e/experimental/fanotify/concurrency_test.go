package fanotify

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestConcurrency reads the small files and overlapping slices of the large
// one all at once from a cold cache, which exercises the fetch pool and the
// coalescing of identical in-flight fetches: every reader gets the right
// bytes, none hangs or is denied, and the daemon survives.
func TestConcurrency(t *testing.T) {
	t.Parallel()
	Fanotify{}.Require(t)
	s := serveDataset(t)
	m := s.mount(t, "")
	src, mnt := s.img.Source, m.Root

	var wg sync.WaitGroup
	errs := make(chan error, manyFiles+8)
	for i := 1; i <= manyFiles; i++ {
		wg.Go(func() {
			errs <- sameFile(filepath.Join(src, manyName(i)), filepath.Join(mnt, manyName(i)))
		})
	}
	// Repeated offsets make readers race for the same cold range.
	for _, mib := range []int64{0, 4, 8, 8, 12, 16, 16, 20} {
		wg.Go(func() {
			errs <- sameRange(filepath.Join(src, largeFile), filepath.Join(mnt, largeFile), mib<<20, 2<<20)
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		t.Fatalf("concurrent readers still blocked after 2m")
	}
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.True(t, m.Daemon.Alive(), "daemon died under concurrent reads")
	requireHealthy(t, m.Daemon)
}
