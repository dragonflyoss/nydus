package contract

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// directIO reports whether path is offered for O_DIRECT. Only a kernel
// EROFS mount may refuse it, with EINVAL: the driver only offers direct I/O
// for some inode layouts (not compressed ones, and file-backed mounts depend
// on the kernel version), which is the kernel's choice, not the image's. The
// nydus FUSE reader must always accept it, so any other outcome reports
// true and leaves the error to openDirect.
func (f *Fixture) directIO(path string) bool {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECT|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		return true
	}

	return !f.isKernelEROFS() || !errors.Is(err, unix.EINVAL)
}

// openDirect opens path with O_DIRECT for the rest of the test.
func openDirect(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECT|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(fd) })

	return fd
}

// openRO opens path read-only for the rest of the test.
func openRO(t *testing.T, path string) int {
	t.Helper()
	// O_CLOEXEC: a daemon another parallel test starts must not inherit the
	// descriptor and keep this mount busy.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(fd) })

	return fd
}

// openDir opens dir for getdents64 for the rest of the test.
func openDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(fd) })

	return fd
}

// mapFile maps length bytes of path for the rest of the test.
func mapFile(t *testing.T, path string, length, prot, flags int) []byte {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = unix.Close(fd) }()
	data, err := unix.Mmap(fd, 0, length, prot, flags)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Munmap(data) })

	return data
}

// openErr opens path with flags and closes it again, returning only the
// error, for the cases that assert on how an open is refused.
func openErr(path string, flags int, mode uint32) error {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, mode)
	if err == nil {
		_ = unix.Close(fd)
	}

	return err
}
