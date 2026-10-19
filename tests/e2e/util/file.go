package util

import (
	"errors"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Sha256File returns the hex SHA-256 of the file at path, streaming so large
// files never sit in memory.
func Sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		return ""
	}
	defer func() { _ = f.Close() }()

	d, err := digest.FromReader(f)
	if !assert.NoError(t, err) {
		return ""
	}

	return d.Encoded()
}

// Sha256Range returns the hex SHA-256 of length bytes of the file at path
// starting at offset.
func Sha256Range(t *testing.T, path string, offset, length int64) string {
	t.Helper()
	data, err := ReadRange(path, offset, length)
	if !assert.NoError(t, err) {
		return ""
	}

	return digest.FromBytes(data).Encoded()
}

// Sha256Tree returns the hex SHA-256 of every regular file under dir, keyed by
// relative path.
func Sha256Tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	hashes := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		hashes[rel] = Sha256File(t, path)
		return nil
	})
	assert.NoError(t, err)

	return hashes
}

// RandomBytes returns size pseudo-random bytes seeded by seed, the same bytes
// for the same seed, so content and the digests derived from it stay
// reproducible across runs.
func RandomBytes(size int, seed int64) []byte {
	// RandomReader never fails or returns short.
	data := make([]byte, size)
	_, _ = io.ReadFull(NewRandomReader(seed), data)

	return data
}

// Inode returns the inode number of the file at path, which identifies the
// file across processes.
func Inode(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	assert.NoError(t, unix.Stat(path, &st))
	return st.Ino
}

// ListFiles returns the set of regular files directly under dir, keyed by
// path.
func ListFiles(t *testing.T, dir string) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)

	files := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			files[filepath.Join(dir, entry.Name())] = struct{}{}
		}
	}

	return files
}

// AllocatedBytes returns the bytes allocated on disk for the file at path,
// not its apparent size: a hole file reports close to zero until a chunk is
// fetched.
func AllocatedBytes(t *testing.T, path string) int64 {
	t.Helper()
	var st unix.Stat_t
	assert.NoError(t, unix.Stat(path, &st))

	return st.Blocks * 512
}

// ReadRange reads length bytes of the file at path starting at offset, short
// at the end of the file.
func ReadRange(path string, offset, length int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if errors.Is(err, io.EOF) {
		err = nil
	}

	return buf[:n], err
}

// ReadWhole reads the file at path to the end and returns its length.
func ReadWhole(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	assert.NoError(t, err)
	defer func() { _ = f.Close() }()

	n, err := io.Copy(io.Discard, f)
	assert.NoError(t, err)

	return n
}

// WriteRandomFile writes size bytes of pseudo-random data to path, seeded by
// the path so the same path always holds the same bytes and different paths
// hold different ones.
func WriteRandomFile(t *testing.T, path string, size int) {
	t.Helper()
	f, err := os.Create(path)
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = f.Close() }()

	seed := fnv.New64a()
	_, _ = seed.Write([]byte(path))
	_, err = io.CopyN(f, NewRandomReader(int64(seed.Sum64())), int64(size))
	assert.NoError(t, err)
}

// RandomReader is a seeded linear congruential generator, so a test can
// regenerate the bytes it wrote without keeping them.
type RandomReader struct {
	// state is the generator state, advanced per byte.
	state uint64
}

// NewRandomReader returns a reader of pseudo-random bytes seeded by seed.
func NewRandomReader(seed int64) *RandomReader {
	return &RandomReader{state: uint64(seed)*2862933555777941757 + 3037000493}
}

// Read fills p with the next pseudo-random bytes.
func (r *RandomReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 33)
	}

	return len(p), nil
}

// TryOpen opens path with flags and mode, closes the descriptor straight away
// and returns the error of the open, so a caller can check how a filesystem
// answers an open without keeping the file.
func TryOpen(path string, flags int, mode uint32) error {
	fd, err := unix.Open(path, flags, mode)
	if err == nil {
		_ = unix.Close(fd)
	}

	return err
}

// InodeMap returns the inode number of every path under root, keyed by
// relative path.
func InodeMap(t *testing.T, root string) map[string]uint64 {
	t.Helper()
	inodes := map[string]uint64{}
	assert.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		inodes[rel] = st.Ino

		return nil
	}))

	return inodes
}
