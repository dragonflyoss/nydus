package dragonfly

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The SDK refreshes seed peers every 60s; allow one refresh after recovery.
const recoveryBound = 90 * time.Second

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
