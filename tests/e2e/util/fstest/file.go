package fstest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// FileSHA256 returns the hex SHA-256 of the file at path, failing t on
// any error.
func FileSHA256(t testing.TB, path string) string {
	t.Helper()
	sum, err := HashFile(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}

	return sum
}

// HashFile returns the hex SHA-256 of the file at path.
func HashFile(path string) (string, error) {
	return hashFile(path, false)
}

// HashFileCold evicts path from the page cache and then hashes it, so the
// bytes come from the filesystem under test rather than the kernel.
func HashFileCold(path string) (string, error) {
	return hashFile(path, true)
}

// hashFile hashes the file at path, evicting it from the page cache first
// when cold is set.
func hashFile(path string, cold bool) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer func() { _ = f.Close() }()

	if cold {
		return HashCold(f)
	}

	return hashReader(f)
}

// HashCold evicts f from the page cache and hashes all of it, whatever its
// current offset.
func HashCold(f *os.File) (string, error) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
	return hashReader(io.NewSectionReader(f, 0, 1<<62))
}

func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ReadAt reads up to n bytes of path at off; a short read at EOF is not an
// error.
func ReadAt(path string, off, n int64) ([]byte, error) {
	return readAt(path, off, n, false)
}

// ReadAtCold evicts [off, off+n) of path from the page cache before reading
// it.
func ReadAtCold(path string, off, n int64) ([]byte, error) {
	return readAt(path, off, n, true)
}

// readAt reads up to n bytes of path at off, evicting that range from the
// page cache first when cold is set.
func readAt(path string, off, n int64, cold bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	if cold {
		_ = unix.Fadvise(int(f.Fd()), off, n, unix.FADV_DONTNEED)
	}

	buf := make([]byte, n)

	got, err := f.ReadAt(buf, off)
	if errors.Is(err, io.EOF) {
		err = nil
	}

	return buf[:got], err
}

// SameRange checks that mnt holds the bytes of src in [off, off+n).
func SameRange(src, mnt string, off, n int64) error {
	want, err := ReadAt(src, off, n)
	if err != nil {
		return err
	}

	got, err := ReadAt(mnt, off, n)
	if err != nil {
		return fmt.Errorf("read %s at %d: %w", mnt, off, err)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("%s: %d bytes at %d differ from the source", mnt, n, off)
	}

	return nil
}

// SameFile checks that mnt holds exactly the bytes of src.
func SameFile(src, mnt string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}

	return SameRange(src, mnt, 0, st.Size()+1)
}

// DropPageCache evicts path from the page cache, so the next read reaches
// the filesystem under test instead of being served by the kernel.
func DropPageCache(t testing.TB, path string) {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	assert.NoError(t, unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED))
}
