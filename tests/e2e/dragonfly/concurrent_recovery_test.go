package dragonfly

//e2e:serial stops and restores the shared Dragonfly cluster.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestConcurrentRecovery(t *testing.T) {
	c := newCluster(t)
	const size = 32 << 20
	img := uniqueImageSize(t, size, "zstd-4k-group-64k")
	origin := startOrigin(t, img)
	m := mountDragonfly(t, c, img, origin.URL, options{FetchSize: mount.Ptr[int64](0)})
	p := &prober{m: m, src: img.Source}
	for off := int64(0); off < size; off += windowStride {
		p.windows = append(p.windows, window{rel: "data", off: off, n: windowSize})
	}
	d, err := p.readBackend(t)
	require.NoError(t, err)
	require.Positive(t, d.of(proxyReads))

	c.stop(t, "dfdaemon", "scheduler")
	d = concurrentBatch(t, p)
	expectFallback(t, d, "concurrent readers during transport outage")
	c.restore(t)
	start := time.Now()
	for {
		d = concurrentBatch(t, p)
		if d.of(proxyReads) > 0 && d.of(fallbackReads) == 0 {
			require.Zero(t, d.of(proxyErrors))
			return
		}
		require.Less(t, time.Since(start), recoveryBound, "concurrent readers must resume P2P without remounting: %v", d)
		time.Sleep(time.Second)
	}
}

func concurrentBatch(t *testing.T, p *prober) delta {
	t.Helper()
	const readers = 4
	type result struct {
		got, want []byte
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, readers)
	for range readers {
		require.Less(t, p.next, len(p.windows), "exhausted cold windows before recovery")
		w := p.windows[p.next]
		p.next++
		source, err := os.Open(filepath.Join(p.src, w.rel))
		require.NoError(t, err)
		want := make([]byte, w.n)
		_, err = source.ReadAt(want, w.off)
		require.NoError(t, err)
		require.NoError(t, source.Close())
		go func() {
			<-start
			got := make([]byte, w.n)
			err := readAt(p.m.Path(w.rel), w.off, got)
			results <- result{got, want, err}
		}()
	}
	return measure(t, p.m, func() {
		within(t, p.m, policyBound, "concurrent on-demand reads", func() {
			close(start)
			for range readers {
				result := <-results
				require.NoError(t, result.err)
				require.Equal(t, result.want, result.got)
			}
		})
	})
}
