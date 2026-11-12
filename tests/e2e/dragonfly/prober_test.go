package dragonfly

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
)

type window struct {
	rel    string
	off, n int64
}

type prober struct {
	m       mounted
	src     string
	windows []window
	next    int
}

func (p *prober) read(t testing.TB) error {
	t.Helper()
	if !assert.Less(t, p.next, len(p.windows)) {
		t.FailNow()
	}

	w := p.windows[p.next]
	p.next++
	want, err := fstest.ReadAt(filepath.Join(p.src, w.rel), w.off, w.n)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	got, err := fstest.ReadAt(p.m.Path(w.rel), w.off, w.n)
	if err != nil {
		return fmt.Errorf("%s at %d: %w", w.rel, w.off, err)
	}
	if !assert.True(t, bytes.Equal(want, got)) {
		t.FailNow()
	}

	return nil
}

func (p *prober) readBackend(t testing.TB) (delta, error) {
	t.Helper()
	for {
		var err error

		d := p.m.measure(t, func() {
			p.m.within(t, readTimeout, "a read", func() { err = p.read(t) })
		})

		if d.of(proxyReads) != 0 {
			return d, err
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}
	}
}

func (p *prober) concurrentBatch(t *testing.T) delta {
	t.Helper()
	const readers = 4

	type result struct {
		got, want []byte
		err       error
	}

	batch := make([]window, readers)
	wants := make([][]byte, readers)

	for i := range readers {
		if !assert.Less(t, p.next, len(p.windows)) {
			t.FailNow()
		}

		batch[i] = p.windows[p.next]
		p.next++
		want, err := fstest.ReadAt(filepath.Join(p.src, batch[i].rel), batch[i].off, batch[i].n)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		wants[i] = want
	}

	return p.m.measure(t, func() {
		p.m.within(t, policyTimeout, "concurrent on-demand reads", func() {
			results := make(chan result, readers)

			for i, w := range batch {
				go func() {
					got, err := fstest.ReadAt(p.m.Path(w.rel), w.off, w.n)
					results <- result{got, wants[i], err}
				}()
			}

			for range readers {
				result := <-results
				if !assert.NoError(t, result.err) {
					t.FailNow()
				}

				assert.True(t, bytes.Equal(result.want, result.got))
			}
		})
	})
}
