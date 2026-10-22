package util

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Dirent is one entry of the raw getdents64 stream of a directory.
type Dirent struct {
	// Name is the entry name.
	Name string

	// Ino is the d_ino of the entry.
	Ino uint64

	// Type is the d_type of the entry.
	Type uint8

	// Off is the d_off of the entry, where the stream resumes after it.
	Off int64
}

// sortedDirents lists dir through a buffer small enough to take several
// getdents64 calls, so readdir resumption is exercised, without "." and
// "..", sorted by name.
func sortedDirents(t *testing.T, dir string) []Dirent {
	t.Helper()
	entries := slices.DeleteFunc(ReadDirents(t, dir, 512), func(e Dirent) bool {
		return e.Name == "." || e.Name == ".."
	})
	slices.SortFunc(entries, func(a, b Dirent) int { return strings.Compare(a.Name, b.Name) })

	return entries
}

// ReadDirents opens dir and returns its raw getdents64 stream, read through
// a buffer of bufSize bytes so a small buffer exercises readdir resumption.
func ReadDirents(t *testing.T, dir string, bufSize int) []Dirent {
	t.Helper()

	// O_CLOEXEC: a builder or daemon another parallel test starts must not
	// inherit the descriptor and keep this mount busy.
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	assert.NoError(t, err, "open %s", dir)
	defer func() { _ = unix.Close(fd) }()

	return DrainDirents(t, fd, bufSize)
}

// DrainDirents decodes the raw getdents64 stream. unix.ParseDirent would be
// simpler but discards d_type, d_ino and d_off, which is precisely what needs
// checking here.
func DrainDirents(t *testing.T, fd int, bufSize int) []Dirent {
	t.Helper()

	buf := make([]byte, bufSize)
	var out []Dirent
	for {
		n, err := unix.Getdents(fd, buf)
		if !assert.NoError(t, err) || n == 0 {
			return out
		}

		for offset := 0; offset < n; {
			raw := (*unix.Dirent)(unsafe.Pointer(&buf[offset]))
			reclen := int(raw.Reclen)
			assert.Greater(t, reclen, 0, "malformed dirent record length")

			nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(&raw.Name[0])), reclen-int(unsafe.Offsetof(raw.Name)))
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}

			out = append(out, Dirent{
				Name: string(nameBytes),
				Ino:  raw.Ino,
				Type: raw.Type,
				Off:  raw.Off,
			})
			offset += reclen
		}
	}
}

// DirentType returns the d_type a directory entry must carry for a file of
// the given st_mode.
func DirentType(mode uint32) uint8 {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return unix.DT_REG
	case unix.S_IFDIR:
		return unix.DT_DIR
	case unix.S_IFLNK:
		return unix.DT_LNK
	case unix.S_IFIFO:
		return unix.DT_FIFO
	case unix.S_IFSOCK:
		return unix.DT_SOCK
	case unix.S_IFCHR:
		return unix.DT_CHR
	case unix.S_IFBLK:
		return unix.DT_BLK
	default:
		return unix.DT_UNKNOWN
	}
}

// DirentNames returns the names of entries in stream order.
func DirentNames(entries []Dirent) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}

	return names
}

// PageAlignedBuffer returns a page-aligned slice of size bytes, which O_DIRECT
// requires.
func PageAlignedBuffer(size int) []byte {
	pageSize := os.Getpagesize()
	raw := make([]byte, size+pageSize)
	offset := int(uintptr(unsafe.Pointer(&raw[0])) % uintptr(pageSize))
	if offset != 0 {
		offset = pageSize - offset
	}

	return raw[offset : offset+size]
}

// MmapFile maps the first length bytes of the file at path with prot and
// flags, and returns the mapping with the function that unmaps it, safe to
// call more than once. A zero length maps nothing, and a mapping that fails
// stops the test since every caller indexes the result.
func MmapFile(t *testing.T, path string, length, prot, flags int) ([]byte, func()) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	assert.NoError(t, err)
	defer func() { _ = unix.Close(fd) }()

	if length == 0 {
		return nil, func() {}
	}

	data, err := unix.Mmap(fd, 0, length, prot, flags)
	if !assert.NoError(t, err, "mmap %s", path) {
		t.FailNow()
	}

	var once sync.Once
	return data, func() { once.Do(func() { _ = unix.Munmap(data) }) }
}

// AlignUp rounds v up to the next multiple of a.
func AlignUp(v, a uint64) uint64 {
	return (v + a - 1) / a * a
}

// AlignDown rounds v down to the previous multiple of a.
func AlignDown(v, a uint64) uint64 {
	return v / a * a
}

// AsUser runs fn with the calling thread's filesystem uid and gid both
// dropped to id. setfsuid is per-thread and, once the fsuid is non-zero, the
// kernel also clears CAP_DAC_OVERRIDE and friends from the effective set, so
// fn meets the permission checks an unprivileged process would.
func AsUser(t *testing.T, id int, fn func() error) error {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	assert.NoError(t, unix.Setfsgid(id))
	assert.NoError(t, unix.Setfsuid(id))
	defer func() {
		_ = unix.Setfsuid(0)
		_ = unix.Setfsgid(0)
	}()

	// setfsuid cannot report failure, and running these checks as root would
	// make every one of them pass, so read the fsuid back before trusting fn.
	assert.EqualValues(t, id, threadFsuid(t), "fsuid was not dropped")

	return fn()
}

// threadFsuid returns the calling thread's filesystem uid, the fourth field
// of the Uid line in /proc/thread-self/status.
func threadFsuid(t *testing.T) int {
	t.Helper()
	status, err := os.ReadFile("/proc/thread-self/status")
	assert.NoError(t, err)

	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}

		fields := strings.Fields(rest)
		if !assert.Len(t, fields, 4, "unexpected Uid line: %q", line) {
			return -1
		}

		fsuid, err := strconv.Atoi(fields[3])
		assert.NoError(t, err)
		return fsuid
	}

	assert.Fail(t, "no Uid line in /proc/thread-self/status")
	return -1
}

// InternalXattrPrefix is the namespace of the xattrs nydus keeps for itself,
// such as trusted.nydus.prefetch.blobs on the image root. The FUSE reader
// hides them, a kernel EROFS mount of the raw device exposes them, and they
// are not part of the tree a mount must reproduce.
const InternalXattrPrefix = "trusted.nydus."

// IsInternalXattr reports whether name is an xattr nydus keeps for itself.
func IsInternalXattr(name string) bool {
	return strings.HasPrefix(name, InternalXattrPrefix)
}

// visibleXattrs lists the xattr names of path that a mount must reproduce,
// the internal ones left out.
func visibleXattrs(t *testing.T, path string) []string {
	t.Helper()
	names := slices.DeleteFunc(ListXattr(t, path), IsInternalXattr)
	if len(names) == 0 {
		return nil
	}

	return names
}

// ListXattr lists the xattr names of path itself, not of a symlink target.
func ListXattr(t *testing.T, path string) []string {
	t.Helper()

	size, err := unix.Llistxattr(path, nil)
	// A nydus mount of an image without any xattr answers EOPNOTSUPP.
	if errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	if !assert.NoError(t, err, "listxattr %s", path) || size == 0 {
		return nil
	}

	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	assert.NoError(t, err)

	var names []string
	for _, raw := range bytes.Split(bytes.TrimRight(buf[:n], "\x00"), []byte{0}) {
		if len(raw) > 0 {
			names = append(names, string(raw))
		}
	}
	slices.Sort(names)

	return names
}

// GetXattr reads an xattr of path itself, not of a symlink target.
func GetXattr(t *testing.T, path, name string) []byte {
	t.Helper()

	size, err := unix.Lgetxattr(path, name, nil)
	if !assert.NoError(t, err, "getxattr %s %s", path, name) || size == 0 {
		return []byte{}
	}

	buf := make([]byte, size)
	n, err := unix.Lgetxattr(path, name, buf)
	assert.NoError(t, err)
	return buf[:n]
}
