package uffd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestFaultCopy(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	img := standardImage(t)
	s := startService(t, img)
	c := s.newFaultClient(t, handshakeCopy, 2<<20)
	c.ack(t)

	want := deviceBytes(t, s.socket, 0, c.deviceSize)
	if !assert.Equal(t, uint32(erofs.SuperMagic), binary.LittleEndian.Uint32(want[erofs.SuperOffset:])) {
		t.FailNow()
	}

	first := waitTouch(t, c.touchAsync(t, 0), faultTimeout, "cold fault at device offset 0")
	if !assert.Equal(t, want[0], first) {
		t.FailNow()
	}

	for off := uint64(0); off < c.deviceSize; off += c.region.faultSize {
		waitTouch(t, c.touchAsync(t, off), faultTimeout, fmt.Sprintf("cold fault at device offset %#x", off))
	}

	cold := c.snapshot(t, 0, c.deviceSize, "cold full-device read")
	if !assert.True(t, bytes.Equal(want, cold)) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(make([]byte, c.blockSize), cold[c.deviceSize-uint64(c.blockSize):])) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(want, c.snapshot(t, 0, c.deviceSize, "warm full-device read"))) {
		t.FailNow()
	}

	t.Run("LoopMount", func(t *testing.T) {
		env.MustHaveRoot(t)
		env.MustHaveKernel(t, 6, 4, "EROFS flatdev mounts of a flattened image")
		env.MustHaveFilesystem(t, "erofs")
		dir := env.WorkDir(t)
		image := filepath.Join(dir, "faulted-device.img")
		if !assert.NoError(t, os.WriteFile(image, cold, 0o644)) {
			t.FailNow()
		}

		mnt := filepath.Join(dir, "mnt")
		if !assert.NoError(t, os.MkdirAll(mnt, 0o755)) {
			t.FailNow()
		}
		if !assert.NoError(t, exec.Command("mount", "-t", "erofs", "-o", "ro,loop", image, mnt).Run()) {
			t.FailNow()
		}

		t.Cleanup(func() { mount.Unmount(mnt) })
		fstest.VerifyMount(t, mnt, img.Want, img.Compare())
	})
}

func TestFaultZerocopy(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, standardImage(t))
	const faultSize = 64 << 10
	c := s.newFaultClient(t, 0, faultSize)
	c.ack(t)
	want := deviceBytes(t, s.socket, 0, c.deviceSize)

	ch := c.touchAsync(t, 0)

	if !assert.NotEmpty(t, c.serveZerocopyFault(t)) {
		t.FailNow()
	}
	if !assert.Equal(t, want[0], waitTouch(t, ch, faultTimeout, "zerocopy fault at device offset 0")) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(want[:faultSize], c.snapshot(t, 0, faultSize, "zerocopy-mapped head"))) {
		t.FailNow()
	}

	tail := c.deviceSize - faultSize
	ch = c.touchAsync(t, tail)
	c.serveZerocopyFault(t)
	assert.Zero(t, waitTouch(t, ch, faultTimeout, "zerocopy fault at the device tail"))

	if !assert.True(t, bytes.Equal(want[tail:], c.snapshot(t, tail, faultSize, "zerocopy-mapped tail"))) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(want[:faultSize], c.snapshot(t, 0, faultSize, "zerocopy-mapped head after the tail fault"))) {
		t.FailNow()
	}
}

func TestFaultZeropage(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, standardImage(t))
	c := s.newFaultClient(t, handshakeCopy, blockSize)
	c.ack(t)

	ranges, fds := fetch(t, s.socket, 0, c.deviceSize)
	defer closeFDs(fds)

	if !assert.NotEmpty(t, ranges) {
		t.FailNow()
	}

	last := ranges[len(ranges)-1]

	if !assert.True(t, isZeroDevice(t, fds[len(fds)-1])) {
		t.FailNow()
	}
	if !assert.Equal(t, c.deviceSize, last.deviceOffset+last.length) {
		t.FailNow()
	}

	target := c.deviceSize - uint64(c.blockSize)
	if !assert.GreaterOrEqual(t, target, last.deviceOffset) {
		t.FailNow()
	}

	b := waitTouch(t, c.touchAsync(t, target), faultTimeout, "zero-page fault at the device tail")
	assert.Zero(t, b)
	assert.True(t, bytes.Equal(make([]byte, c.blockSize), c.snapshot(t, target, uint64(c.blockSize), "zero-page tail")))
}

func TestPrefaultAndBatching(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, layeredImage(t, 20))

	want := deviceBytes(t, s.socket, 0, s.deviceSize(t))

	c := s.newFaultClient(t, handshakePrefault, 2<<20)
	ranges, fds, frames := c.readRanges(t, caseTimeout)
	defer closeFDs(fds)

	if !assert.Greater(t, len(ranges), maxRangesPerMsg) {
		t.FailNow()
	}

	assert.GreaterOrEqual(t, frames, 2)
	c.mapRanges(t, ranges, fds, false)
	c.ack(t)

	if !assert.True(t, bytes.Equal(want, c.snapshot(t, 0, c.deviceSize, "read of the prefault-mapped device"))) {
		t.FailNow()
	}
}

func TestBackendFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, blob string)
	}{
		{"Truncated", func(t *testing.T, blob string) { assert.NoError(t, os.Truncate(blob, 1024)) }},
		{"Removed", func(t *testing.T, blob string) { assert.NoError(t, os.Remove(blob)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Copy(t, standardImage(t))
			for _, blob := range img.Blobs {
				tc.damage(t, blob)
			}

			s := startService(t, img)
			deviceSize := s.deviceSize(t)

			for range 2 {
				conn := dial(t, s.socket)
				t.Cleanup(func() { _ = conn.Close() })
				conn.send(t, msgFetch, encodeRange(0, deviceSize))
				conn.expectClosed(t)
			}

			s.expectAlive(t, deviceSize)
		})
	}
}
