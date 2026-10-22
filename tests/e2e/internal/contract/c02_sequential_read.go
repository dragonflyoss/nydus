package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C02: every regular file reads back front to back, whatever the read size,
// from a cold page cache, including into buffers that are themselves mapped
// from the mount.
func init() {
	Register(Case{ID: "C02", Name: "SequentialRead", Scope: Data, Run: runSequentialRead})
}

// seqBufSizes are the read sizes files are cycled through: a single byte,
// one under and exactly a block, just over a FUSE request, and 1MiB.
var seqBufSizes = []int{1, 4095, 4096, 128<<10 + 1, 1 << 20}

// faultInLimit bounds the file the fault-in reads use.
const faultInLimit = 8 << 20

func runSequentialRead(t *testing.T, f *Fixture) {
	t.Run("BufferSizes", func(t *testing.T) {
		t.Parallel()
		for i, e := range hashedFiles(f.Image.Want) {
			size := seqBufSizes[i%len(seqBufSizes)]
			if size == 1 && e.Size > 8<<10 {
				// A byte at a time costs a syscall per byte; keep it to small files.
				size = 511
			}
			sum, n, err := sequentialHash(f.At(string(e.Path)), size)
			require.NoError(t, err, "read %s with a %d byte buffer", e.Path, size)
			require.Equal(t, e.Size, n, "%s: bytes read with a %d byte buffer", e.Path, size)
			require.Equal(t, e.SHA256, sum, "%s: content read with a %d byte buffer", e.Path, size)
		}
	})

	t.Run("FaultIn", func(t *testing.T) {
		t.Parallel()
		faultIn(t, f)
	})
}

// hashedFiles returns the regular files of want whose whole content hash is
// recorded, i.e. those small enough to read in full.
func hashedFiles(want []oracle.Entry) []oracle.Entry {
	var out []oracle.Entry
	for _, e := range want {
		if e.Type == "reg" && e.SHA256 != "" {
			out = append(out, e)
		}
	}
	return out
}

// sequentialHash reads path with read(2) calls of bufSize bytes, after
// dropping its cached pages so the reads reach the filesystem.
func sequentialHash(path string, bufSize int) (string, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	_ = unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)

	h := sha256.New()
	buf := make([]byte, bufSize)
	var total int64
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", total, err
		}
		if n == 0 {
			return hex.EncodeToString(h.Sum(nil)), total, nil
		}
		h.Write(buf[:n])
		total += int64(n)
	}
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
		require.NoError(t, err, what)
	case <-time.After(d):
		t.Fatalf("%s did not finish within %s", what, d)
	}
}

// isKernelEROFS reports whether the adapter serves the image through the
// kernel EROFS driver rather than the nydus FUSE reader; every adapter but
// FUSE does. Where the two legitimately differ the cases branch on it.
func isKernelEROFS(f *Fixture) bool {
	return f.Adapter.Name() != "fuse"
}

// openDirect opens path with O_DIRECT. ok is false when a kernel EROFS
// mount refuses it with EINVAL: the driver only offers direct I/O for some
// inode layouts (not compressed ones, and file-backed mounts depend on the
// kernel version), which is the kernel's choice, not the image's. The nydus
// FUSE reader must always accept it.
func openDirect(t *testing.T, f *Fixture, path string) (fd int, ok bool) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECT|unix.O_CLOEXEC, 0)
	if err != nil && isKernelEROFS(f) && errors.Is(err, unix.EINVAL) {
		t.Logf("%s: O_DIRECT not offered by kernel EROFS here", path)
		return -1, false
	}
	require.NoError(t, err, "open %s with O_DIRECT", path)
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd, true
}

// faultIn reads into a destination buffer that is itself a private mapping
// of a file on the same mount. Servicing the read has to fault that page in,
// which issues a second request while the first is still in flight; a
// filesystem that serializes the two deadlocks, so every read runs under a
// watchdog.
func faultIn(t *testing.T, f *Fixture) {
	src, backing := faultInFiles(t, f.Image.Want)
	srcPath, backingPath := f.At(string(src.Path)), f.At(string(backing.Path))
	want, err := os.ReadFile(srcPath)
	require.NoError(t, err)
	sum := sha256.Sum256(want)
	require.Equal(t, src.SHA256, hex.EncodeToString(sum[:]), "%s: content", src.Path)

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
	mapped := func(t *testing.T, path string) []byte {
		t.Helper()
		buf := mapFile(t, path, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		return buf
	}

	t.Run("Pread", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, srcPath)
		buf := mapped(t, backingPath)
		within(t, 30*time.Second, "pread into a mapped buffer", func() error {
			n, err := unix.Pread(fd, buf, 0)
			return check(buf, n, err, len(want))
		})
	})

	t.Run("Preadv", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, srcPath)
		buf := mapped(t, backingPath)
		half := len(buf) / 2
		within(t, 30*time.Second, "preadv into mapped buffers", func() error {
			n, err := unix.Preadv(fd, [][]byte{buf[:half], buf[half:]}, 0)
			return check(buf, n, err, len(want))
		})
	})

	t.Run("Direct", func(t *testing.T) {
		t.Parallel()
		fd, ok := openDirect(t, f, srcPath)
		if !ok {
			return
		}
		// O_DIRECT needs block-aligned lengths; the mapping is page aligned.
		buf := mapped(t, backingPath)
		length := len(want) &^ 4095
		within(t, 30*time.Second, "O_DIRECT read into a mapped buffer", func() error {
			n, err := unix.Pread(fd, buf[:length], 0)
			return check(buf, n, err, length)
		})
	})

	t.Run("SameFile", func(t *testing.T) {
		t.Parallel()
		// The tightest case: the fault lands on a page of the very file the
		// read is serving.
		fd := openRO(t, srcPath)
		buf := mapped(t, srcPath)
		within(t, 30*time.Second, "pread into a mapping of the same file", func() error {
			n, err := unix.Pread(fd, buf, 0)
			return check(buf, n, err, len(want))
		})
	})
}

// faultInFiles picks the file to read, preferably the largest block-aligned
// one up to faultInLimit so O_DIRECT can read all of it, and a different
// file at least as large to map the destination buffer from.
func faultInFiles(t *testing.T, want []oracle.Entry) (src, backing oracle.Entry) {
	t.Helper()
	better := func(e, than oracle.Entry) bool {
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
	require.NotEmpty(t, src.Path, "the image has no regular file to fault in")
	backing = src
	for _, e := range files {
		if e.Path != src.Path && e.Size >= src.Size && (backing.Path == src.Path || e.Size < backing.Size) {
			backing = e
		}
	}
	return src, backing
}
