package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var seqBufSizes = []int{1, 4095, 4096, 128<<10 + 1, 1 << 20}

func runSequentialRead(t *testing.T, f *Fixture) {
	t.Run("BufferSizes", func(t *testing.T) {
		t.Parallel()
		for i, e := range hashedFiles(f.Image.Want) {
			size := seqBufSizes[i%len(seqBufSizes)]
			if size == 1 && e.Size > 8<<10 {
				// A byte at a time costs a syscall per byte; keep it to small files.
				size = 511
			}

			sum, n, err := sequentialHash(f.Path(string(e.Path)), size)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, e.Size, n) {
				t.FailNow()
			}

			assert.Equal(t, e.SHA256, sum)
		}
	})

	t.Run("FaultIn", func(t *testing.T) {
		t.Parallel()
		faultIn(t, f)
	})
}

// faultIn reads into a destination buffer that is itself a private mapping
// of a file on the same mount. Servicing the read has to fault that page in,
// which issues a second request while the first is still in flight; a
// filesystem that serializes the two deadlocks, so every read runs under a
// watchdog.
func faultIn(t *testing.T, f *Fixture) {
	src, backing := faultInFiles(t, f.Image.Want)
	srcPath, backingPath := f.Path(string(src.Path)), f.Path(string(backing.Path))
	want, err := os.ReadFile(srcPath)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	sum := sha256.Sum256(want)
	assert.Equal(t, src.SHA256, hex.EncodeToString(sum[:]))

	check := func(buf []byte, n int, err error, length int) error {
		if err != nil {
			return err
		}
		if n != length {
			return fmt.Errorf("read %d of %d bytes", n, length)
		}
		if !bytes.Equal(want[:n], buf[:n]) {
			return fmt.Errorf("read different bytes")
		}

		return nil
	}

	t.Run("SameFile", func(t *testing.T) {
		t.Parallel()
		// The tightest case: the fault lands on a page of the very file the
		// read is serving.
		fd := openRO(t, srcPath)
		buf := mapFile(t, srcPath, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)

		within(t, faultInTimeout, "pread into a mapping of the same file", func() error {
			n, err := unix.Pread(fd, buf, 0)
			return check(buf, n, err, len(want))
		})
	})

	if backing.Path == src.Path {
		return
	}

	t.Run("Pread", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, srcPath)
		buf := mapFile(t, backingPath, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)

		within(t, faultInTimeout, "pread into a mapped buffer", func() error {
			n, err := unix.Pread(fd, buf, 0)
			return check(buf, n, err, len(want))
		})
	})

	t.Run("Preadv", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, srcPath)
		buf := mapFile(t, backingPath, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		half := len(buf) / 2

		within(t, faultInTimeout, "preadv into mapped buffers", func() error {
			n, err := unix.Preadv(fd, [][]byte{buf[:half], buf[half:]}, 0)
			return check(buf, n, err, len(want))
		})
	})

	if !f.directIO(srcPath) {
		return
	}

	t.Run("Direct", func(t *testing.T) {
		t.Parallel()
		fd := openDirect(t, srcPath)
		// O_DIRECT needs block-aligned lengths; the mapping is page aligned.
		buf := mapFile(t, backingPath, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		length := len(want) &^ 4095

		within(t, faultInTimeout, "O_DIRECT read into a mapped buffer", func() error {
			n, err := unix.Pread(fd, buf[:length], 0)
			return check(buf, n, err, length)
		})
	})
}

// faultInFiles picks the file to read, preferably the largest block-aligned
// one up to faultInLimit so O_DIRECT can read all of it, and the smallest
// other file at least as large to map the destination buffer from; backing
// is src itself when there is no such file.
func faultInFiles(t *testing.T, want []fstest.Entry) (src, backing fstest.Entry) {
	t.Helper()
	better := func(e, than fstest.Entry) bool {
		if aligned, thanAligned := e.Size%4096 == 0, than.Size%4096 == 0; aligned != thanAligned {
			return aligned
		}

		return e.Size > than.Size
	}

	files := hashedFiles(want)
	for _, e := range files {
		if e.Size > 0 && e.Size <= faultInLimit && (src.Path == "" || better(e, src)) {
			src = e
		}
	}

	if !assert.NotEmpty(t, src.Path) {
		t.FailNow()
	}

	backing = src

	for _, e := range files {
		if e.Path != src.Path && e.Size >= src.Size && (backing.Path == src.Path || e.Size < backing.Size) {
			backing = e
		}
	}

	return src, backing
}

// within runs fn and fails t unless it returns within d. A deadlock in a
// read path shows up as a hang, which would otherwise stall CI until the
// global timeout. fn must not call t: it runs on another goroutine.
func within(t *testing.T, d time.Duration, what string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)

	go func() { done <- fn() }()

	select {
	case err := <-done:
		assert.NoError(t, err)

	case <-time.After(d):
		t.Fatalf("%s did not finish within %s", what, d)
	}
}
