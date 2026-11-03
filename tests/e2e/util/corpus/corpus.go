// Package corpus generates the source trees the images under test are built
// from: a builder that creates real files, directories, links, device nodes
// and xattrs on disk, and the named corpora the fixtures cache.
package corpus

import (
	"encoding/binary"
	"hash/fnv"
	randv2 "math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Bytes returns n pseudo-random bytes derived from seed, the same on every
// run, so a test can know a file's content without keeping it.
func Bytes(seed uint64, n int) []byte {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], seed)
	out := make([]byte, n)
	_, _ = randv2.NewChaCha8(key).Read(out)

	return out
}

// Corpus represents a directory tree used as input to `nydus build`.
type Corpus struct {
	Dir string
}

// New creates a fresh corpus directory at dir (removed if it existed).
func New(t testing.TB, dir string) *Corpus {
	t.Helper()
	if !assert.NoError(t, os.RemoveAll(dir)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.MkdirAll(dir, 0o755)) {
		t.FailNow()
	}

	return &Corpus{Dir: dir}
}

// path returns the absolute path for a relative name inside the corpus.
func (c *Corpus) path(name string) string {
	return filepath.Join(c.Dir, name)
}

// parent creates the parent directory of name and returns the absolute
// path of name.
func (c *Corpus) parent(t testing.TB, name string) string {
	t.Helper()
	path := c.path(name)
	if !assert.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755)) {
		t.FailNow()
	}

	return path
}

// CreateFile writes data to a regular file.
func (c *Corpus) CreateFile(t testing.TB, name string, data []byte) {
	t.Helper()
	assert.NoError(t, os.WriteFile(c.parent(t, name), data, 0o644))
}

// CreateRandomFile creates a file of size incompressible bytes derived from
// name, the same on every run.
func (c *Corpus) CreateRandomFile(t testing.TB, name string, size int) {
	t.Helper()
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	c.CreateFile(t, name, Bytes(h.Sum64(), size))
}

// createPatternFile creates a file with a repeating 0x00..0xFF byte pattern.
func (c *Corpus) createPatternFile(t testing.TB, name string, repeatCount int) {
	t.Helper()
	pattern := make([]byte, 256)
	for i := range pattern {
		pattern[i] = byte(i)
	}

	var buf []byte

	for range repeatCount {
		buf = append(buf, pattern...)
	}

	assert.NoError(t, os.WriteFile(c.parent(t, name), buf, 0o644))
}

// CreateZeroFile creates a file filled with size bytes of zeros.
func (c *Corpus) CreateZeroFile(t testing.TB, name string, size int) {
	t.Helper()
	assert.NoError(t, os.WriteFile(c.parent(t, name), make([]byte, size), 0o644))
}

// CreateSparseFile creates a sparse file with the provided size and writes.
func (c *Corpus) CreateSparseFile(t testing.TB, name string, size int64, writes map[int64][]byte) {
	t.Helper()
	path := c.parent(t, name)
	f, err := os.Create(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() {
		assert.NoError(t, f.Close())
	}()

	for offset, data := range writes {
		_, err := f.WriteAt(data, offset)
		assert.NoError(t, err)
	}

	assert.NoError(t, f.Truncate(size))
}

// CreateDir creates a directory (and parents).
func (c *Corpus) CreateDir(t testing.TB, name string) {
	t.Helper()
	assert.NoError(t, os.MkdirAll(c.path(name), 0o755))
}

// CreateSymlink creates a symbolic link name -> target (relative to corpus).
func (c *Corpus) CreateSymlink(t testing.TB, name, target string) {
	t.Helper()
	assert.NoError(t, os.Symlink(target, c.parent(t, name)))
}

// CreateHardlink creates a hard link name -> existing file target (relative to corpus).
func (c *Corpus) CreateHardlink(t testing.TB, name, target string) {
	t.Helper()
	assert.NoError(t, os.Link(c.path(target), c.parent(t, name)))
}

// CreateFIFO creates a named pipe.
func (c *Corpus) CreateFIFO(t testing.TB, name string) {
	t.Helper()
	assert.NoError(t, unix.Mkfifo(c.parent(t, name), 0o666))
}

// CreateUnixSocket creates a filesystem socket node. Nothing listens on it:
// the node is all an image records, and a bound listener would have to be
// closed (and the node removed) before the corpus could be cached.
func (c *Corpus) CreateUnixSocket(t testing.TB, name string) {
	t.Helper()
	assert.NoError(t, unix.Mknod(c.parent(t, name), unix.S_IFSOCK|0o777, 0))
}

// CreateCharDev creates a character device node (requires root).
func (c *Corpus) CreateCharDev(t testing.TB, name string, major, minor uint32) {
	t.Helper()
	path := c.parent(t, name)
	dev := int(unix.Mkdev(major, minor))
	assert.NoError(t, unix.Mknod(path, unix.S_IFCHR|0o666, dev))
}

// CreateBlockDev creates a block device node (requires root).
func (c *Corpus) CreateBlockDev(t testing.TB, name string, major, minor uint32) {
	t.Helper()
	path := c.parent(t, name)
	dev := int(unix.Mkdev(major, minor))
	assert.NoError(t, unix.Mknod(path, unix.S_IFBLK|0o666, dev))
}

// Chmod sets the raw mode bits. os.Chmod is not usable here: its os.FileMode
// encodes setuid, setgid and sticky outside the low twelve bits, so passing an
// octal mode such as 04755 through it silently drops the setuid bit.
func (c *Corpus) Chmod(t testing.TB, name string, mode uint32) {
	t.Helper()
	assert.NoError(t, unix.Chmod(c.path(name), mode))
}

// Chown sets uid and gid (requires root).
func (c *Corpus) Chown(t testing.TB, name string, uid, gid int) {
	t.Helper()
	assert.NoError(t, os.Lchown(c.path(name), uid, gid))
}

// SetXattr sets an extended attribute.
func (c *Corpus) SetXattr(t testing.TB, name, key string, value []byte) {
	t.Helper()
	assert.NoError(t, unix.Setxattr(c.path(name), key, value, 0))
}

// setTimes sets the access and modification time, without following symlinks.
// Timestamps decide whether the builder can use a compact inode, whose mtime is
// a 32-bit seconds count with no nanoseconds.
func (c *Corpus) setTimes(t testing.TB, name string, sec, nsec int64) {
	t.Helper()
	ts := unix.Timespec{Sec: sec, Nsec: nsec}
	assert.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, c.path(name), []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW))
}

const (
	aclVersion   = 2
	aclUserObj   = 0x01
	aclUser      = 0x02
	aclGroupObj  = 0x04
	aclGroup     = 0x08
	aclMask      = 0x10
	aclOther     = 0x20
	aclUndefined = 0xFFFFFFFF
)

// aclEntry is one entry of a POSIX ACL.
type aclEntry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

// minimalACL returns the three entries every valid ACL needs, plus a named user
// and the mask that a named entry requires.
func minimalACL(namedUID uint32) []aclEntry {
	return []aclEntry{
		{Tag: aclUserObj, Perm: 6, ID: aclUndefined},
		{Tag: aclUser, Perm: 4, ID: namedUID},
		{Tag: aclGroupObj, Perm: 4, ID: aclUndefined},
		{Tag: aclMask, Perm: 6, ID: aclUndefined},
		{Tag: aclOther, Perm: 4, ID: aclUndefined},
	}
}

// setACL writes a POSIX ACL. EROFS stores these under their own xattr name
// index rather than as a user attribute, so they exercise an encoding path that
// user.* attributes do not reach.
func (c *Corpus) setACL(t testing.TB, name string, entries []aclEntry, defaultACL bool) {
	t.Helper()
	buf := make([]byte, 4+len(entries)*8)
	binary.LittleEndian.PutUint32(buf, aclVersion)

	for i, e := range entries {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(buf[off:], e.Tag)
		binary.LittleEndian.PutUint16(buf[off+2:], e.Perm)
		binary.LittleEndian.PutUint32(buf[off+4:], e.ID)
	}

	key := "system.posix_acl_access"
	if defaultACL {
		key = "system.posix_acl_default"
	}

	assert.NoError(t, unix.Setxattr(c.path(name), key, buf, 0))
}

// SetFileCaps attaches a VFS capability set, the vfs_cap_data v2 layout from
// include/uapi/linux/capability.h. Container images routinely carry these on
// binaries such as ping, so the builder has to preserve security.* verbatim.
func (c *Corpus) SetFileCaps(t testing.TB, name string, permitted, inheritable uint32) {
	t.Helper()
	const vfsCapRevision = 0x02000000
	const effectiveBit = 0x000001

	buf := make([]byte, 20)
	binary.LittleEndian.PutUint32(buf, vfsCapRevision|effectiveBit)
	binary.LittleEndian.PutUint32(buf[4:], permitted)
	binary.LittleEndian.PutUint32(buf[8:], inheritable)
	assert.NoError(t, unix.Setxattr(c.path(name), "security.capability", buf, 0))
}
