package committer

import (
	"sync/atomic"
)

type Counter struct {
	n int64
}

func (c *Counter) Write(p []byte) (n int, err error) {
	atomic.AddInt64(&c.n, int64(len(p)))
	return len(p), nil
}

func (c *Counter) Size() (n int64) {
	return c.n
}
