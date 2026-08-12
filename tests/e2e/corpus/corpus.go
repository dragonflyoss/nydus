// Package corpus provides helpers for generating an NydusFS filesystem test
// corpus.
//
// The Corpus type follows a builder pattern (originally modeled on the
// upstream image-service smoke tests' layer builder) and creates real files
// on disk to exercise the `nydus build` and `nydus fuse` code paths.
package corpus

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Corpus represents a directory tree used as input to `nydus build`.
type Corpus struct {
	Dir string
}

// NewCorpus creates a fresh corpus directory at dir (removed if it existed).
func NewCorpus(t *testing.T, dir string) *Corpus {
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(dir, 0755))
	return &Corpus{Dir: dir}
}

// path returns the absolute path for a relative name inside the corpus.
func (c *Corpus) path(name string) string {
	return filepath.Join(c.Dir, name)
}

// CreateFile writes data to a regular file.
func (c *Corpus) CreateFile(t *testing.T, name string, data []byte) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.WriteFile(c.path(name), data, 0644))
}

// CreateRandomFile creates a file with exactly size bytes of random data.
func (c *Corpus) CreateRandomFile(t *testing.T, name string, size int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	f, err := os.Create(c.path(name))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})

	_, err = io.CopyN(f, rand.Reader, int64(size))
	require.NoError(t, err)
}

// CreatePatternFile creates a file with a repeating 0x00..0xFF byte pattern.
func (c *Corpus) CreatePatternFile(t *testing.T, name string, repeatCount int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	pattern := make([]byte, 256)
	for i := range pattern {
		pattern[i] = byte(i)
	}

	var buf []byte
	for range repeatCount {
		buf = append(buf, pattern...)
	}

	require.NoError(t, os.WriteFile(c.path(name), buf, 0644))
}

// CreateZeroFile creates a file filled with size bytes of zeros.
func (c *Corpus) CreateZeroFile(t *testing.T, name string, size int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.WriteFile(c.path(name), make([]byte, size), 0644))
}

// CreateSparseFile creates a sparse file with the provided size and writes.
func (c *Corpus) CreateSparseFile(t *testing.T, name string, size int64, writes map[int64][]byte) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	f, err := os.Create(c.path(name))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	for offset, data := range writes {
		_, err := f.WriteAt(data, offset)
		require.NoError(t, err)
	}
	require.NoError(t, f.Truncate(size))
}

// CreateDir creates a directory (and parents).
func (c *Corpus) CreateDir(t *testing.T, name string) {
	require.NoError(t, os.MkdirAll(c.path(name), 0755))
}

// CreateSymlink creates a symbolic link name -> target (relative to corpus).
func (c *Corpus) CreateSymlink(t *testing.T, name, target string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.Symlink(target, c.path(name)))
}

// CreateHardlink creates a hard link name -> existing file target (relative to corpus).
func (c *Corpus) CreateHardlink(t *testing.T, name, target string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.Link(c.path(target), c.path(name)))
}

// CreateFIFO creates a named pipe.
func (c *Corpus) CreateFIFO(t *testing.T, name string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, syscall.Mkfifo(c.path(name), 0666))
}

// CreateUnixSocket creates a filesystem socket node.
func (c *Corpus) CreateUnixSocket(t *testing.T, name string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	listener, err := net.Listen("unix", c.path(name))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		err := os.Remove(c.path(name))
		if err != nil && !os.IsNotExist(err) {
			require.NoError(t, err)
		}
	})
}

// CreateCharDev creates a character device node (requires root).
func (c *Corpus) CreateCharDev(t *testing.T, name string, major, minor uint32) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	dev := int(unix.Mkdev(major, minor))
	require.NoError(t, syscall.Mknod(c.path(name), syscall.S_IFCHR|0666, dev))
}

// CreateBlockDev creates a block device node (requires root).
func (c *Corpus) CreateBlockDev(t *testing.T, name string, major, minor uint32) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	dev := int(unix.Mkdev(major, minor))
	require.NoError(t, syscall.Mknod(c.path(name), syscall.S_IFBLK|0666, dev))
}

// Chmod sets the file mode (permission bits + special bits).
// Chmod sets the raw mode bits. os.Chmod is not usable here: its os.FileMode
// encodes setuid, setgid and sticky outside the low twelve bits, so passing an
// octal mode such as 04755 through it silently drops the setuid bit.
func (c *Corpus) Chmod(t *testing.T, name string, mode uint32) {
	require.NoError(t, unix.Chmod(c.path(name), mode))
}

// Chown sets uid and gid (requires root).
func (c *Corpus) Chown(t *testing.T, name string, uid, gid int) {
	require.NoError(t, os.Lchown(c.path(name), uid, gid))
}

// SetXattr sets an extended attribute.
func (c *Corpus) SetXattr(t *testing.T, name, key string, value []byte) {
	require.NoError(t, xattr.Set(c.path(name), key, value))
}

// SetTimes sets the access and modification time, without following symlinks.
// Timestamps decide whether the builder can use a compact inode, whose mtime is
// a 32-bit seconds count with no nanoseconds.
func (c *Corpus) SetTimes(t *testing.T, name string, sec, nsec int64) {
	ts := unix.Timespec{Sec: sec, Nsec: nsec}
	require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, c.path(name), []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW))
}

// POSIX ACL on-disk constants, from include/uapi/linux/posix_acl_xattr.h.
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

// ACLEntry is one entry of a POSIX ACL.
type ACLEntry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

// MinimalACL returns the three entries every valid ACL needs, plus a named user
// and the mask that a named entry requires.
func MinimalACL(namedUID uint32) []ACLEntry {
	return []ACLEntry{
		{Tag: aclUserObj, Perm: 6, ID: aclUndefined},
		{Tag: aclUser, Perm: 4, ID: namedUID},
		{Tag: aclGroupObj, Perm: 4, ID: aclUndefined},
		{Tag: aclMask, Perm: 6, ID: aclUndefined},
		{Tag: aclOther, Perm: 4, ID: aclUndefined},
	}
}

// SetACL writes a POSIX ACL. EROFS stores these under their own xattr name
// index rather than as a user attribute, so they exercise an encoding path that
// user.* attributes do not reach.
func (c *Corpus) SetACL(t *testing.T, name string, entries []ACLEntry, defaultACL bool) {
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
	require.NoError(t, xattr.Set(c.path(name), key, buf))
}

// SetFileCaps attaches a VFS capability set, the vfs_cap_data v2 layout from
// include/uapi/linux/capability.h. Container images routinely carry these on
// binaries such as ping, so the builder has to preserve security.* verbatim.
func (c *Corpus) SetFileCaps(t *testing.T, name string, permitted, inheritable uint32) {
	const revision2 = 0x02000000
	const effectiveBit = 0x000001

	buf := make([]byte, 20)
	binary.LittleEndian.PutUint32(buf, revision2|effectiveBit)
	binary.LittleEndian.PutUint32(buf[4:], permitted)
	binary.LittleEndian.PutUint32(buf[8:], inheritable)
	require.NoError(t, xattr.Set(c.path(name), "security.capability", buf))
}

// LongName returns a string of n repeated characters, useful for edge-case filenames.
func LongName(ch byte, n int) string {
	return strings.Repeat(string(ch), n)
}

// MakeStandardCorpus populates a corpus with the full set of test cases
// matching the original gen_test_corpus.sh.
func MakeStandardCorpus(t *testing.T, dir string) *Corpus {
	c := NewCorpus(t, dir)

	// Regular files.
	c.CreateFile(t, "files/empty", nil)
	c.CreateFile(t, "files/tiny_2b", []byte("hi"))
	c.CreateFile(t, "files/small_100b", []byte(strings.Repeat(".", 100)))
	c.CreateFile(t, "files/just_under_block", []byte(strings.Repeat("A", 4095)))
	c.CreateRandomFile(t, "files/exact_block", 4096)
	c.CreateRandomFile(t, "files/one_over_block", 4097)
	c.CreateRandomFile(t, "files/two_blocks", 4096*2)
	c.CreateRandomFile(t, "files/ten_blocks", 4096*10)
	c.CreateRandomFile(t, "files/large_256k", 256*1024)
	c.CreateZeroFile(t, "files/all_zeros", 4096*4)
	c.CreateSparseFile(t, "files/sparse_hole", 4096*4+513, map[int64][]byte{
		0:            []byte("HEAD"),
		4096 - 2:     []byte("EDGE"),
		4096*2 + 17:  []byte("MID"),
		4096*4 + 512: []byte("Z"),
	})
	c.CreatePatternFile(t, "files/byte_pattern", 16)

	// Permissions.
	c.CreateFile(t, "perms/r_only", []byte("readable"))
	c.Chmod(t, "perms/r_only", 0444)
	c.CreateFile(t, "perms/r_x", []byte("executable"))
	c.Chmod(t, "perms/r_x", 0555)
	c.CreateFile(t, "perms/rwx", []byte("all perms"))
	c.Chmod(t, "perms/rwx", 0777)
	c.CreateFile(t, "perms/no_perm", []byte("no perms"))
	c.Chmod(t, "perms/no_perm", 0000)
	c.CreateFile(t, "perms/setuid", []byte("setuid"))
	c.Chmod(t, "perms/setuid", 04755)
	c.CreateFile(t, "perms/setgid", []byte("setgid"))
	c.Chmod(t, "perms/setgid", 02755)
	c.CreateFile(t, "perms/sticky", []byte("sticky"))
	c.Chmod(t, "perms/sticky", 01755)
	c.CreateFile(t, "perms/suid_sgid", []byte("setuid+setgid"))
	c.Chmod(t, "perms/suid_sgid", 06755)

	// Owned by another user so an unprivileged reader falls through to the
	// "other" permission bits rather than the owner's.
	c.CreateFile(t, "perms/other_owner_r", []byte("other readable"))
	c.Chown(t, "perms/other_owner_r", 4000, 4000)
	c.Chmod(t, "perms/other_owner_r", 0444)
	c.CreateFile(t, "perms/other_owner_none", []byte("other unreadable"))
	c.Chown(t, "perms/other_owner_none", 4000, 4000)
	c.Chmod(t, "perms/other_owner_none", 0600)

	// A directory an unprivileged user may traverse but not list, and one it
	// may list but not traverse.
	c.CreateDir(t, "perms/x_only_dir")
	c.CreateFile(t, "perms/x_only_dir/hidden", []byte("reachable by name"))
	c.Chown(t, "perms/x_only_dir", 4000, 4000)
	c.Chmod(t, "perms/x_only_dir", 0711)
	c.CreateDir(t, "perms/r_only_dir")
	c.CreateFile(t, "perms/r_only_dir/listed", []byte("listed but unreachable"))
	c.Chown(t, "perms/r_only_dir", 4000, 4000)
	c.Chmod(t, "perms/r_only_dir", 0444)

	// Directories.
	c.CreateDir(t, "dirs/empty_dir")
	c.CreateDir(t, "dirs/a/b/c/d/e/f")
	c.CreateFile(t, "dirs/a/b/c/d/e/f/deep_file", []byte("deep"))
	c.CreateDir(t, "dirs/many_entries")
	for i := 1; i <= 200; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/many_entries/file_%04d", i),
			fmt.Appendf(nil, "entry_%d", i))
	}

	c.CreateDir(t, "dirs/restricted")
	c.Chmod(t, "dirs/restricted", 0500)
	c.CreateDir(t, "dirs/sticky_dir")
	c.Chmod(t, "dirs/sticky_dir", 01777)

	// Symbolic links.
	c.CreateFile(t, "symlinks/target_file", []byte("target"))
	c.CreateSymlink(t, "symlinks/link_to_file", "target_file")
	c.CreateDir(t, "symlinks/target_dir")
	c.CreateFile(t, "symlinks/target_dir/inner", []byte("in_dir"))
	c.CreateSymlink(t, "symlinks/link_to_dir", "target_dir")
	c.CreateSymlink(t, "symlinks/relative_link", "../files/tiny_2b")
	longName := LongName('x', 200)
	c.CreateFile(t, "symlinks/"+longName, []byte("long"))
	c.CreateSymlink(t, "symlinks/link_to_long_name", longName)
	c.CreateSymlink(t, "symlinks/dangling", "nonexistent_target")
	c.CreateFile(t, "symlinks/chain_c", []byte("chain_end"))
	c.CreateSymlink(t, "symlinks/chain_b", "chain_c")
	c.CreateSymlink(t, "symlinks/chain_a", "chain_b")

	// Loops. Resolving these must stop with ELOOP rather than recurse.
	c.CreateSymlink(t, "symlinks/self_loop", "self_loop")
	c.CreateSymlink(t, "symlinks/loop_a", "loop_b")
	c.CreateSymlink(t, "symlinks/loop_b", "loop_a")

	// A chain longer than the kernel's 40-link budget, the shape generic/005
	// uses.
	c.CreateFile(t, "symlinks/deep_target", []byte("deep"))
	prev := "deep_target"
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("symlinks/deep_%02d", i)
		c.CreateSymlink(t, name, prev)
		prev = fmt.Sprintf("deep_%02d", i)
	}

	// Hard links.
	c.CreateFile(t, "hardlinks/original", []byte("shared content"))
	c.CreateHardlink(t, "hardlinks/link1", "hardlinks/original")
	c.CreateHardlink(t, "hardlinks/link2", "hardlinks/original")
	c.CreateDir(t, "hardlinks/subdir")
	c.CreateHardlink(t, "hardlinks/subdir/link3", "hardlinks/original")
	c.CreateFile(t, "hardlinks/same_content_a", []byte("not actually linked"))
	c.CreateFile(t, "hardlinks/same_content_b", []byte("not actually linked"))

	// Special files (root only).
	c.CreateFIFO(t, "special/fifo")
	c.CreateCharDev(t, "special/chardev", 1, 3)
	c.CreateBlockDev(t, "special/blkdev", 1, 0)
	c.CreateFile(t, "special/other_uid", []byte("other_owner"))
	c.Chown(t, "special/other_uid", 1000, 1000)
	c.CreateFile(t, "special/large_uid_gid", []byte("large numeric owner"))
	c.Chown(t, "special/large_uid_gid", 70000, 70001)

	// A compact EROFS inode stores uid and gid as 16 bits, so these two files
	// straddle the point where the builder has to widen the inode.
	c.CreateFile(t, "special/uid_65535", []byte("last compact owner"))
	c.Chown(t, "special/uid_65535", 65535, 65535)
	c.CreateFile(t, "special/uid_65536", []byte("first extended owner"))
	c.Chown(t, "special/uid_65536", 65536, 65536)
	c.CreateFile(t, "special/root_owned", []byte("root_only"))
	c.Chown(t, "special/root_owned", 0, 0)
	c.Chmod(t, "special/root_owned", 0600)

	// Extended attributes.
	c.CreateFile(t, "xattrs/user_basic", []byte("xattr test\n"))
	c.SetXattr(t, "xattrs/user_basic", "user.test", []byte("hello"))

	c.CreateFile(t, "xattrs/user_multi", []byte("multi xattr\n"))
	c.SetXattr(t, "xattrs/user_multi", "user.key1", []byte("value1"))
	c.SetXattr(t, "xattrs/user_multi", "user.key2", []byte("value2"))
	c.SetXattr(t, "xattrs/user_multi", "user.key3", []byte("value3"))

	c.CreateFile(t, "xattrs/user_empty_val", []byte("empty val\n"))
	c.SetXattr(t, "xattrs/user_empty_val", "user.empty", []byte{})

	c.CreateFile(t, "xattrs/user_binary", []byte("binary xattr\n"))
	c.SetXattr(t, "xattrs/user_binary", "user.bin", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	c.CreateFile(t, "xattrs/user_long_val", []byte("long val\n"))
	c.SetXattr(t, "xattrs/user_long_val", "user.longval", []byte(strings.Repeat("A", 512)))

	c.CreateFile(t, "xattrs/user_long_name", []byte("long name\n"))
	c.SetXattr(t, "xattrs/user_long_name", "user."+LongName('x', 200), []byte("long_name_test"))

	c.CreateDir(t, "xattrs/dir_with_xattr")
	c.SetXattr(t, "xattrs/dir_with_xattr", "user.dirattr", []byte("dir_value"))

	c.CreateFile(t, "xattrs/empty_file_xattr", nil)
	c.SetXattr(t, "xattrs/empty_file_xattr", "user.on_empty", []byte("has_xattr"))

	c.CreateRandomFile(t, "xattrs/large_file_xattr", 4096*4)
	c.SetXattr(t, "xattrs/large_file_xattr", "user.on_large", []byte("large_file"))

	c.CreateFile(t, "xattrs/user_huge_ibody", []byte("huge xattr body\n"))
	for i := 0; i < 3; i++ {
		value := strings.Repeat(string(rune('A'+i)), 900)
		c.SetXattr(t, "xattrs/user_huge_ibody", fmt.Sprintf("user.large_%02d", i), []byte(value))
	}

	c.CreateDir(t, "xattrs/dir_huge_ibody")
	for i := 0; i < 3; i++ {
		value := strings.Repeat(string(rune('k'+i)), 850)
		c.SetXattr(t, "xattrs/dir_huge_ibody", fmt.Sprintf("user.dir_large_%02d", i), []byte(value))
	}

	c.CreateFile(t, "xattrs/security_attr", []byte("security xattr\n"))
	c.SetXattr(t, "xattrs/security_attr", "security.test", []byte("sec_value"))

	c.CreateFile(t, "xattrs/trusted_attr", []byte("trusted xattr\n"))
	c.SetXattr(t, "xattrs/trusted_attr", "trusted.test", []byte("trusted_value"))

	// Filenames with edge cases.
	c.CreateFile(t, "names/"+LongName('a', 250), []byte("long name"))
	c.CreateFile(t, "names/file with spaces", []byte("spaces"))
	c.CreateFile(t, "names/file-with-dashes", []byte("special chars"))
	c.CreateFile(t, "names/file_with_underscores", []byte("special chars"))
	c.CreateFile(t, "names/file.with.dots", []byte("special chars"))
	c.CreateFile(t, "names/UPPERCASE", []byte("special chars"))
	c.CreateFile(t, "names/MiXeD.CaSe", []byte("special chars"))
	c.CreateFile(t, "names/x", []byte("x"))
	c.CreateFile(t, "names/1", []byte("1"))
	c.CreateFile(t, "names/.hidden", []byte("hidden"))
	c.CreateDir(t, "names/.hidden_dir")
	c.CreateFile(t, "names/.hidden_dir/file", []byte("in hidden dir"))

	return c
}

// MakePerfCorpus creates a corpus designed to amplify performance differences between NydusFS and erofsfuse.
func MakePerfCorpus(t *testing.T, dir string) {
	c := NewCorpus(t, dir)
	largeFileCount := EnvInt("NYDUSFS_PERF_LARGE_FILE_COUNT", 8)
	largeFileSize := EnvInt("NYDUSFS_PERF_LARGE_FILE_SIZE", 64*1024*1024)
	mediumFileCount := EnvInt("NYDUSFS_PERF_MEDIUM_FILE_COUNT", 256)
	mediumFileSize := EnvInt("NYDUSFS_PERF_MEDIUM_FILE", 1024*1024)
	smallFileCount := EnvInt("NYDUSFS_PERF_SMALL_FILE_COUNT", 10000)
	readdirDirs := EnvInt("NYDUSFS_PERF_READDIR_DIRS", 128)
	readdirFilesPerDir := EnvInt("NYDUSFS_PERF_READDIR_FILES_PER_DIR", 256)

	for i := range largeFileCount {
		// largeFileSize is in bytes (NYDUSFS_PERF_LARGE_FILE_SIZE, default
		// 64 MiB). An earlier revision passed it to a helper that treated it
		// as MiB, asking for 64 TiB per file and filling the disk.
		c.CreateRandomFile(t, fmt.Sprintf("large/file_%d.bin", i), largeFileSize)
	}

	for i := range mediumFileCount {
		c.CreateRandomFile(t, fmt.Sprintf("medium/file_%04d.bin", i), mediumFileSize)
	}

	for i := range smallFileCount {
		c.CreateFile(t, fmt.Sprintf("small/file_%04d.txt", i),
			fmt.Appendf(nil, "content of small file %d\n", i))
	}

	// Large directory fan-out amplifies readdir cost and triggers repeated
	// FUSE readdir calls.
	for d := range readdirDirs {
		for f := range readdirFilesPerDir {
			c.CreateFile(t, fmt.Sprintf("dirs/d%02d/f%03d.txt", d, f),
				fmt.Appendf(nil, "d%d/f%d", d, f))
		}
	}

	// A small xattr-bearing tree for the listxattr/getxattr benchmarks.
	for i := range 64 {
		name := fmt.Sprintf("xattrs/file_%02d", i)
		c.CreateFile(t, name, fmt.Appendf(nil, "xattr file %d\n", i))
		c.SetXattr(t, name, "user.bench", []byte("value"))
	}
}

// EnvInt reads an environment variable as an integer, returning a default value if the variable is
// not set or cannot be parsed.
func EnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return parsed
}

// MakeStressCorpus builds a large, deliberately awkward tree from a fixed seed.
//
// It is a superset of MakeStandardCorpus: that tree enumerates the cases a
// human thinks of and the suites reference several of its paths by name, while
// the additions here go after the shapes that only show up at volume. The
// dimensions and their weights come from measuring what fstests' own fsstress
// and fsx produce, which is far more hostile than a hand-written list: an
// fsstress+fsx run yields ~1000 entries with 285 sparse files, 328 special
// files, 166 symlinks and directories 13 deep, against roughly 250 entries, one
// sparse file and depth 6 for the standard corpus.
//
// Reimplementing the shape rather than shelling out to fsstress keeps the tree
// deterministic and drops the dependency on a built fstests checkout.
func MakeStressCorpus(t *testing.T, dir string, seed int64) *Corpus {
	t.Helper()

	c := MakeStandardCorpus(t, dir)
	rng := mathrand.New(mathrand.NewSource(seed))

	stressDeepTree(t, c, rng)
	stressWideDirs(t, c, rng)
	stressSparse(t, c, rng)
	stressSpecial(t, c, rng)
	stressLinks(t, c, rng)
	stressXattrs(t, c, rng)
	stressNames(t, c)
	stressRawNames(t, c)
	stressDirentPacking(t, c)
	stressSizes(t, c, rng)
	stressInodeWidth(t, c)
	stressSecurity(t, c)

	return c
}

// stressSecurity covers the attribute namespaces a container image actually
// carries and that user.* does not reach: POSIX ACLs, which EROFS gives their
// own xattr name index, plus the capability and SELinux labels that live under
// security.*.
func stressSecurity(t *testing.T, c *Corpus) {
	c.CreateDir(t, "security")

	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("security/acl_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.SetACL(t, name, MinimalACL(uint32(1000+i)), false)
	}

	// Default ACLs only apply to directories and are stored separately from the
	// access ACL, so a directory carrying both holds two distinct attributes.
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("security/acl_dir_%02d", i)
		c.CreateDir(t, name)
		c.SetACL(t, name, MinimalACL(uint32(2000+i)), false)
		c.SetACL(t, name, MinimalACL(uint32(3000+i)), true)
	}

	// An ACL long enough to spill out of the inline xattr area. The kernel
	// requires entries in tag order with named users ascending by id, so the
	// extra users go between user_obj and group_obj rather than on the end.
	big := []ACLEntry{{Tag: aclUserObj, Perm: 6, ID: aclUndefined}}
	for i := 0; i < 60; i++ {
		big = append(big, ACLEntry{Tag: aclUser, Perm: 4, ID: uint32(5000 + i)})
	}
	big = append(big,
		ACLEntry{Tag: aclGroupObj, Perm: 4, ID: aclUndefined},
		ACLEntry{Tag: aclMask, Perm: 6, ID: aclUndefined},
		ACLEntry{Tag: aclOther, Perm: 4, ID: aclUndefined},
	)
	c.CreateFile(t, "security/acl_many_entries", []byte("x"))
	c.SetACL(t, "security/acl_many_entries", big, false)

	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("security/caps_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.Chmod(t, name, 0o755)
		c.SetFileCaps(t, name, uint32(1<<(i%32)), 0)
	}

	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("security/selinux_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.SetXattr(t, name, "security.selinux",
			[]byte(fmt.Sprintf("system_u:object_r:container_file_t:s0:c%d\x00", i)))
	}
}

// stressInodeWidth targets the compact/extended inode decision, which is the
// densest cluster of encoding branches in the builder. An EROFS compact inode
// stores i_size in 32 bits and mtime in 32 bits with no nanoseconds, so a file
// past 4GiB or a timestamp past 2038 has to be promoted to the 64-byte extended
// form. fsstress reaches these through setattr and truncate; here they are
// stated directly.
func stressInodeWidth(t *testing.T, c *Corpus) {
	c.CreateDir(t, "inode")

	// Sparse, so a 5GiB file costs a few blocks on disk.
	for _, spec := range []struct {
		name string
		size int64
	}{
		{"size_4g_minus_1", (4 << 30) - 1},
		{"size_4g", 4 << 30},
		{"size_4g_plus_1", (4 << 30) + 1},
		{"size_5g", 5 << 30},
	} {
		c.CreateSparseFile(t, "inode/"+spec.name, spec.size, map[int64][]byte{
			0:              []byte("head"),
			spec.size - 16: []byte("tail"),
		})
	}

	for _, spec := range []struct {
		name string
		sec  int64
		nsec int64
	}{
		{"mtime_epoch", 0, 0},
		{"mtime_nsec", 1_600_000_000, 123_456_789},
		{"mtime_2038_before", (1 << 31) - 2, 0},
		{"mtime_2038_after", (1 << 31) + 2, 0},
		{"mtime_2106_after", (1 << 32) + 2, 0},
		{"mtime_far_future", 4_000_000_000, 999_999_999},
	} {
		name := "inode/" + spec.name
		c.CreateFile(t, name, []byte(spec.name))
		c.SetTimes(t, name, spec.sec, spec.nsec)
	}

	// A link count that needs more than the 16 bits a compact inode can spare.
	c.CreateFile(t, "inode/many_links", []byte("shared"))
	c.CreateDir(t, "inode/links")
	for i := 0; i < 300; i++ {
		c.CreateHardlink(t, fmt.Sprintf("inode/links/l%04d", i), "inode/many_links")
	}

	// Hardlinks to something other than a regular file: fsstress links any
	// non-directory, and the builder has to keep the type with the shared inode.
	c.CreateFIFO(t, "inode/fifo_orig")
	c.CreateHardlink(t, "inode/fifo_link", "inode/fifo_orig")
	c.CreateUnixSocket(t, "inode/sock_orig")
	c.CreateHardlink(t, "inode/sock_link", "inode/sock_orig")
	if os.Getuid() == 0 {
		c.CreateCharDev(t, "inode/chr_orig", 1, 3)
		c.CreateHardlink(t, "inode/chr_link", "inode/chr_orig")
	}

	// Symlink targets up to PATH_MAX. 4064 is the last size that still rides
	// inline behind a compact inode (EROFS_BLOCK_SIZE minus the 32-byte header);
	// anything above it has to fall back to a block of its own, so the sizes
	// straddling that boundary are the ones worth having.
	for _, n := range []int{1, 255, 256, 1023, 1024, 4032, 4064, 4065, 4090, 4095} {
		c.CreateSymlink(t, fmt.Sprintf("inode/symlink_target_%04d", n), LongName('t', n))
	}
}

// stressDeepTree nests to 13 levels, past anything the standard corpus reaches,
// and drops a file at every level so lookup has to walk the whole chain.
func stressDeepTree(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	path := "deep"
	for depth := 1; depth <= 13; depth++ {
		path = fmt.Sprintf("%s/d%02d", path, depth)
		c.CreateDir(t, path)
		c.CreateRandomFile(t, path+"/leaf", 1+rng.Intn(8192))
		if depth%3 == 0 {
			c.CreateSymlink(t, fmt.Sprintf("%s/up%02d", path, depth), "../..")
		}
	}
}

// stressWideDirs spans many EROFS directory blocks: a 4KiB block holds roughly
// 200 short entries, so these cross the boundary repeatedly and with name
// lengths that make the split land mid-entry.
func stressWideDirs(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	for _, spec := range []struct {
		dir     string
		count   int
		nameLen func(i int) int
	}{
		{"wide/short", 2000, func(int) int { return 3 }},
		{"wide/mixed", 1200, func(i int) int { return 1 + i%255 }},
		{"wide/long", 400, func(int) int { return 255 }},
	} {
		c.CreateDir(t, spec.dir)
		for i := 0; i < spec.count; i++ {
			name := fmt.Sprintf("%0*d", spec.nameLen(i), i)
			if len(name) > 255 {
				name = name[:255]
			}
			c.CreateFile(t, spec.dir+"/"+name, []byte{byte(i)})
		}
		_ = rng
	}
}

// stressSparse is the dimension the standard corpus barely covers: holes that
// start and end at every interesting offset relative to the 4KiB block and the
// chunk size.
func stressSparse(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	offsets := []int64{0, 1, 4095, 4096, 4097, 8191, 65535, 65536, 1 << 20}
	for i, off := range offsets {
		size := off + int64(1+rng.Intn(9000))
		c.CreateSparseFile(t, fmt.Sprintf("sparse/hole_at_%d", i), size, map[int64][]byte{
			off: []byte("DATA"),
		})
	}

	// Data islands separated by holes, so a single read spans hole-data-hole.
	for i := 0; i < 40; i++ {
		writes := map[int64][]byte{}
		for j := 0; j < 1+rng.Intn(6); j++ {
			writes[int64(j)*(4096*int64(1+rng.Intn(4)))+int64(rng.Intn(64))] =
				[]byte(strings.Repeat("x", 1+rng.Intn(300)))
		}
		c.CreateSparseFile(t, fmt.Sprintf("sparse/islands_%02d", i), 1<<20, writes)
	}

	// Entirely hole: nothing but a size.
	c.CreateSparseFile(t, "sparse/all_hole", 4<<20, nil)

	// Alternating hole and data at block granularity, the shape xfstests
	// generates with punch-alternating. It maximises the number of hole entries
	// the chunk index has to encode.
	for _, blocks := range []int{16, 64, 256} {
		writes := map[int64][]byte{}
		for b := 0; b < blocks; b += 2 {
			writes[int64(b)*4096] = []byte(strings.Repeat("D", 4096))
		}
		c.CreateSparseFile(t, fmt.Sprintf("sparse/alternating_%03d", blocks),
			int64(blocks)*4096, writes)
	}
}

// stressSpecial creates the device, fifo and socket nodes in bulk. fsstress
// produces hundreds of these; the standard corpus has three.
func stressSpecial(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "special")
	for i := 0; i < 60; i++ {
		c.CreateFIFO(t, fmt.Sprintf("special/fifo_%02d", i))
	}
	for i := 0; i < 40; i++ {
		c.CreateUnixSocket(t, fmt.Sprintf("special/sock_%02d", i))
	}
	if os.Getuid() != 0 {
		return
	}
	// Sweep major/minor past 8 bits so the rdev encoding has to widen.
	for i := 0; i < 60; i++ {
		major := uint32(rng.Intn(4096))
		minor := uint32(rng.Intn(1 << 20))
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%02d", i), major, minor)
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%02d", i), major, minor)
	}
}

// stressLinks builds hardlink groups of varying size plus symlink chains and
// loops, which is where nlink accounting and path resolution tend to break.
func stressLinks(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "links")
	for group := 0; group < 20; group++ {
		target := fmt.Sprintf("links/target_%02d", group)
		c.CreateRandomFile(t, target, 1+rng.Intn(4096))
		for n := 0; n < 1+rng.Intn(8); n++ {
			c.CreateHardlink(t, fmt.Sprintf("links/hard_%02d_%02d", group, n), target)
		}
	}

	// A chain long enough to approach, but not exceed, the kernel's 40-link limit.
	for i := 0; i < 30; i++ {
		c.CreateSymlink(t, fmt.Sprintf("links/chain_%02d", i), fmt.Sprintf("chain_%02d", i+1))
	}
	c.CreateFile(t, "links/chain_30", []byte("chain end"))

	for i := 0; i < 20; i++ {
		c.CreateSymlink(t, fmt.Sprintf("links/dangling_%02d", i), fmt.Sprintf("missing_%02d", i))
	}
	c.CreateSymlink(t, "links/abs", c.Dir+"/links/chain_30")
}

// stressXattrs pushes past the inline xattr body of an EROFS inode, where the
// builder has to spill into the shared xattr area.
//
// Sizes stay well under 4KiB per inode because the corpus is staged on ext4,
// which keeps all of an inode's attributes in a single block. That is still far
// more than the EROFS inline body holds, so the spill path is exercised.
func stressXattrs(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "xattr")
	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("xattr/f_%02d", i)
		c.CreateRandomFile(t, name, 1+rng.Intn(1024))
		count := 1 + i%8
		for j := 0; j < count; j++ {
			c.SetXattr(t, name,
				fmt.Sprintf("user.a%02d", j),
				[]byte(strings.Repeat("v", 1+rng.Intn(256))))
		}
	}

	// Many files sharing one identical attribute exercises deduplication.
	shared := []byte(strings.Repeat("shared", 100))
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("xattr/shared_%02d", i)
		c.CreateFile(t, name, []byte{byte(i)})
		c.SetXattr(t, name, "user.common", shared)
	}

	c.CreateFile(t, "xattr/maxname", []byte("x"))
	c.SetXattr(t, "xattr/maxname", "user."+LongName('n', 250), []byte("v"))
	c.CreateFile(t, "xattr/bigvalue", []byte("x"))
	c.SetXattr(t, "xattr/bigvalue", "user.big", []byte(strings.Repeat("V", 3000)))

	// One inode carrying many small attributes. EROFS counts the inline xattr
	// area in 4-byte units, so the count rather than the byte total is what is
	// under test here. The staging filesystem caps an inode at 4 KiB of
	// attributes, which is what bounds this at 120.
	c.CreateFile(t, "xattr/many", []byte("x"))
	for i := 0; i < 120; i++ {
		c.SetXattr(t, "xattr/many", fmt.Sprintf("user.m%03d", i), []byte{byte(i)})
	}
}

// stressNames covers the full 1..255 byte range plus the byte sequences that
// tend to be mishandled between the builder and the dirent encoder.
func stressNames(t *testing.T, c *Corpus) {
	c.CreateDir(t, "names")
	for n := 1; n <= 255; n++ {
		c.CreateFile(t, "names/"+strings.Repeat("n", n), []byte{byte(n)})
	}
	for i, name := range []string{
		" leading", "trailing ", "mid space", "tab\there", "quote'sq", `quote"dq`,
		"back\\slash", "star*", "question?", "brack[et]", "dollar$", "semi;colon",
		"utf8-中文", "utf8-🙂", "dot.", "..dots", "-dash", "~tilde",
	} {
		c.CreateFile(t, "names/"+name, []byte{byte(i)})
	}
	// Sorting boundary: one name is a strict prefix of the other.
	for _, name := range []string{"pre", "pre0", "preA", "prea", "pre_", "pre~"} {
		c.CreateFile(t, "names/"+name, []byte(name))
	}
}

// stressRawNames uses names that are not valid UTF-8. A Linux filename is any
// byte sequence except '/' and NUL, so anything that routes a name through a
// UTF-8 string rewrites the invalid bytes and can make two distinct names
// collide into one directory entry.
func stressRawNames(t *testing.T, c *Corpus) {
	c.CreateDir(t, "rawnames")

	raw := [][]byte{
		[]byte("latin1_caf\xe9"),
		[]byte("cp1252_\x93quoted\x94"),
		[]byte("shift_jis_\x83\x65\x83\x58\x83\x67"),
		[]byte("gbk_\xd6\xd0\xce\xc4"),
		[]byte("lone_surrogate_\xed\xa0\x80"),
		[]byte("overlong_\xc0\xaf"),
		[]byte("truncated_\xe4\xb8"),
		[]byte("bare_fe_\xfe"),
		[]byte("bare_ff_\xff"),
		[]byte("ctrl_\x01\x02\x1f\x7f"),
		[]byte("newline_\n_in_name"),
		{0xff},
		{0xfe, 0xff},
	}
	for _, name := range raw {
		c.CreateFile(t, "rawnames/"+string(name), name)
	}

	// Distinct names that a lossy conversion would fold together, and names
	// whose relative order such a conversion would invert.
	for _, name := range [][]byte{
		[]byte("collide_\xfe"), []byte("collide_\xff"), []byte("collide_\xfe\xfe"),
		[]byte("\xf0zzz"), []byte("\xfeaaa"), []byte("\xefzzz"),
	} {
		c.CreateFile(t, "rawnames/"+string(name), name)
	}
}

// stressDirentPacking targets the EROFS directory block layout, where each
// entry costs a 12-byte header at the head of the block plus its name at the
// tail. These directories land exactly on, just under and just over the
// 4096-byte block boundary.
func stressDirentPacking(t *testing.T, c *Corpus) {
	const blockSize = 4096
	const direntSize = 12

	// "." and ".." are entries too, and they sort first here.
	base := 2*direntSize + 1 + 2

	// Names of a fixed length, chosen so the last entry ends exactly at the
	// boundary, one byte short of it, and one byte past it.
	for _, delta := range []int{-1, 0, 1} {
		nameLen := 30
		dir := fmt.Sprintf("packing/exact_%d", delta+1)
		c.CreateDir(t, "packing")
		c.CreateDir(t, dir)

		used := base
		i := 0
		for used+direntSize+nameLen <= blockSize+delta {
			c.CreateFile(t, fmt.Sprintf("%s/%s%04d", dir, LongName('p', nameLen-4), i), nil)
			used += direntSize + nameLen
			i++
		}
	}

	// A single 255-byte name in a block of its own, and a block filled with
	// them: 12+255 per entry means 15 entries fill 4005 of 4096 bytes, so the
	// sixteenth spills into a second block.
	c.CreateDir(t, "packing/maxname")
	for i := 0; i < 16; i++ {
		c.CreateFile(t, fmt.Sprintf("packing/maxname/%s%03d", LongName('m', 252), i), nil)
	}

	// Names differing only in their last bytes. The kernel binary-searches
	// dirents by byte comparison, so a shared 250-byte prefix makes every probe
	// compare the full name.
	c.CreateDir(t, "packing/shared_prefix")
	prefix := LongName('s', 250)
	for i := 0; i < 400; i++ {
		c.CreateFile(t, fmt.Sprintf("packing/shared_prefix/%s%04d", prefix, i), nil)
	}

	c.CreateDir(t, "packing/empty")
	c.CreateDir(t, "packing/single")
	c.CreateFile(t, "packing/single/only", []byte("only"))
}

// stressSizes brackets every chunk-size boundary the build matrix uses.
func stressSizes(t *testing.T, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "sizes")
	for _, chunk := range []int{4096, 64 << 10, 1 << 20} {
		for _, mult := range []int{1, 2, 3} {
			for _, delta := range []int{-1, 0, 1} {
				size := chunk*mult + delta
				if size <= 0 {
					continue
				}
				c.CreateRandomFile(t, fmt.Sprintf("sizes/c%d_m%d_d%d", chunk, mult, delta), size)
			}
		}
	}
	// One file well past any chunk size, built from a hole plus a tail so it
	// costs almost nothing on disk.
	c.CreateSparseFile(t, "sizes/large_12m", 12<<20, map[int64][]byte{
		0:                []byte("head"),
		(12 << 20) - 512: []byte("tail"),
	})
	_ = rng
}
