package uffd

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type faultClient struct {
	conn       client
	uffd       int
	mem        []byte
	deviceSize uint64
	blockSize  uint32
	region     vmaRegion
	touchers   sync.WaitGroup
	closeOnce  sync.Once
}

func (s *service) newFaultClient(t testing.TB, flags byte, faultSize uint64) *faultClient {
	t.Helper()
	c := &faultClient{conn: dial(t, s.socket), uffd: -1}
	t.Cleanup(func() { c.close(t) })

	c.deviceSize, c.blockSize = c.conn.stat(t)
	if !assert.Positive(t, c.deviceSize) {
		t.FailNow()
	}

	mem, err := unix.Mmap(-1, 0, int(c.deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	c.mem = mem
	c.uffd, err = newUserfaultfd()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	if !assert.NoError(t, registerMissing(c.uffd, base, c.deviceSize)) {
		t.FailNow()
	}

	c.region = vmaRegion{
		virtAddr:  base,
		size:      c.deviceSize,
		faultSize: faultSize,
		prot:      int32(unix.PROT_READ | unix.PROT_WRITE),
		flags:     int32(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
	}

	c.conn.handshake(t, flags, []vmaRegion{c.region}, c.uffd)

	return c
}

func (c *faultClient) close(t testing.TB) {
	t.Helper()
	c.closeOnce.Do(func() {
		_ = c.conn.Close()

		if c.uffd >= 0 {
			_ = unix.Close(c.uffd)
		}

		if c.mem == nil {
			return
		}

		done := make(chan struct{})

		go func() { c.touchers.Wait(); close(done) }()

		select {
		case <-done:
			assert.NoError(t, unix.Munmap(c.mem))

		case <-time.After(caseTimeout):

			t.Errorf("touchers still blocked %v after every userfaultfd was closed; leaking the VMA", caseTimeout)
		}
	})
}

func (c *faultClient) ack(t testing.TB) {
	t.Helper()
	size, _ := c.conn.stat(t)
	assert.Equal(t, c.deviceSize, size)
}

func (c *faultClient) touchAsync(t testing.TB, off uint64) <-chan byte {
	ch := make(chan byte, 1)
	c.touchers.Add(1)

	go func() {
		defer c.touchers.Done()
		var b [1]byte
		local := []unix.Iovec{{Base: &b[0], Len: 1}}
		remote := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&c.mem[off])), Len: 1}}

		for {
			n, err := unix.ProcessVMReadv(os.Getpid(), local, remote, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if !assert.NoError(t, err) || !assert.Equal(t, 1, n) {
				return
			}

			break
		}

		ch <- b[0]
	}()

	return ch
}

func waitTouch(t testing.TB, ch <-chan byte, timeout time.Duration, desc string) byte {
	t.Helper()
	select {
	case b := <-ch:
		return b

	case <-time.After(timeout):
		t.Fatalf("page fault did not complete within %v: %s", timeout, desc)
		return 0
	}
}

func (c *faultClient) snapshot(t testing.TB, off, n uint64, desc string) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	c.touchers.Add(1)

	go func() {
		defer c.touchers.Done()
		buf := make([]byte, n)
		copy(buf, c.mem[off:off+n])
		ch <- buf
	}()

	select {
	case buf := <-ch:
		return buf

	case <-time.After(caseTimeout):
		t.Fatalf("device read did not complete within %v: %s", caseTimeout, desc)
		return nil
	}
}

func (c *faultClient) readRanges(t testing.TB, timeout time.Duration) ([]deviceRange, []int, int) {
	t.Helper()
	var ranges []deviceRange
	var fds []int
	var frames int
	c.conn.withReadDeadline(t, timeout, func() { ranges, fds, frames = c.conn.readRangeResponse(t) })

	return ranges, fds, frames
}

func (c *faultClient) serveZerocopyFault(t testing.TB) []deviceRange {
	t.Helper()
	ranges, fds, _ := c.readRanges(t, faultTimeout)
	c.mapRanges(t, ranges, fds, true)
	closeFDs(fds)

	return ranges
}

func (c *faultClient) mapRanges(t testing.TB, ranges []deviceRange, fds []int, wake bool) {
	t.Helper()
	if !assert.NotEmpty(t, ranges) {
		t.FailNow()
	}
	if !assert.Len(t, fds, len(ranges)) {
		t.FailNow()
	}

	pageSize := uint64(unix.Getpagesize())
	lo, hi := ^uint64(0), uint64(0)

	for i, r := range ranges {
		if !assert.GreaterOrEqual(t, r.deviceOffset, c.region.offset) {
			t.FailNow()
		}
		if !assert.LessOrEqual(t, r.deviceOffset+r.length, c.region.offset+c.region.size) {
			t.FailNow()
		}

		delta := r.deviceOffset - c.region.offset
		lo = min(lo, c.region.virtAddr+delta)
		hi = max(hi, c.region.virtAddr+delta+r.length)

		if isZeroDevice(t, fds[i]) {
			zstart, zend := alignUp(delta, pageSize), alignUp(delta+r.length, pageSize)
			if zstart < zend {
				addr := unsafe.Add(unsafe.Pointer(&c.mem[0]), int(zstart))

				_, err := unix.MmapPtr(-1, 0, addr, uintptr(zend-zstart),
					unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED)

				assert.NoError(t, err)
			}

			continue
		}

		if !assert.Zero(t, delta%pageSize) {
			t.FailNow()
		}
		if !assert.Zero(t, r.fileOffset%pageSize) {
			t.FailNow()
		}

		addr := unsafe.Add(unsafe.Pointer(&c.mem[0]), int(delta))
		_, err := unix.MmapPtr(fds[i], int64(r.fileOffset), addr, uintptr(r.length), unix.PROT_READ, unix.MAP_PRIVATE|unix.MAP_FIXED)
		assert.NoError(t, err)
	}

	if wake {
		start := alignDown(lo, pageSize)
		arg := uffdioRangeArg{start: start, len: alignUp(hi, pageSize) - start}
		assert.NoError(t, uffdIoctl(c.uffd, uffdioWake, unsafe.Pointer(&arg)))
	}
}
