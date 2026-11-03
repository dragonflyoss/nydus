package conformance

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func (m *mounted) directIO(path string) bool {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECT|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		return true
	}

	return !m.isKernelEROFS() || !errors.Is(err, unix.EINVAL)
}

func openDirect(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECT|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(fd) })

	return fd
}

func openRO(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(fd) })

	return fd
}

func openDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(fd) })

	return fd
}

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

func openErr(path string, flags int, mode uint32) error {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, mode)
	if err == nil {
		_ = unix.Close(fd)
	}

	return err
}
