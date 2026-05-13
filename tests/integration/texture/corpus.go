// Package texture provides helpers for generating EROFS filesystem test corpus.
//
// The Corpus type follows a builder pattern similar to nydus smoke/tests/tool/layer.go,
// creating real files on disk to exercise `lepton mkfs` and `lepton fuse mount` code paths.
package texture

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Corpus represents a directory tree used as input to `lepton mkfs`.
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

// ---------- files ----------

// CreateFile writes data to a regular file.
func (c *Corpus) CreateFile(t *testing.T, name string, data []byte) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.WriteFile(c.path(name), data, 0644))
}

// CreateLargeFile fills a file with sizeMB megabytes of random data.
func (c *Corpus) CreateLargeFile(t *testing.T, name string, sizeMB int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	f, err := os.Create(c.path(name))
	require.NoError(t, err)
	defer f.Close()
	_, err = io.CopyN(f, rand.Reader, int64(sizeMB)<<20)
	require.NoError(t, err)
}

// CreateRandomFile creates a file with exactly size bytes of random data.
func (c *Corpus) CreateRandomFile(t *testing.T, name string, size int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	f, err := os.Create(c.path(name))
	require.NoError(t, err)
	defer f.Close()
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
	for i := 0; i < repeatCount; i++ {
		buf = append(buf, pattern...)
	}
	require.NoError(t, os.WriteFile(c.path(name), buf, 0644))
}

// CreateZeroFile creates a file filled with size bytes of zeros.
func (c *Corpus) CreateZeroFile(t *testing.T, name string, size int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.WriteFile(c.path(name), make([]byte, size), 0644))
}

// ---------- directories ----------

// CreateDir creates a directory (and parents).
func (c *Corpus) CreateDir(t *testing.T, name string) {
	require.NoError(t, os.MkdirAll(c.path(name), 0755))
}

// ---------- symlinks ----------

// CreateSymlink creates a symbolic link name -> target (target is stored as-is).
func (c *Corpus) CreateSymlink(t *testing.T, name, target string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.Symlink(target, c.path(name)))
}

// ---------- hard links ----------

// CreateHardlink creates a hard link name -> existing file target (relative to corpus).
func (c *Corpus) CreateHardlink(t *testing.T, name, target string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, os.Link(c.path(target), c.path(name)))
}

// ---------- special files ----------

// CreateFIFO creates a named pipe.
func (c *Corpus) CreateFIFO(t *testing.T, name string) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	require.NoError(t, syscall.Mkfifo(c.path(name), 0666))
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

// ---------- permissions ----------

// Chmod sets the file mode (permission bits + special bits).
func (c *Corpus) Chmod(t *testing.T, name string, mode os.FileMode) {
	require.NoError(t, os.Chmod(c.path(name), mode))
}

// Chown sets uid and gid (requires root).
func (c *Corpus) Chown(t *testing.T, name string, uid, gid int) {
	require.NoError(t, os.Lchown(c.path(name), uid, gid))
}

// ---------- xattr ----------

// SetXattr sets an extended attribute.
func (c *Corpus) SetXattr(t *testing.T, name, key string, value []byte) {
	require.NoError(t, xattr.Set(c.path(name), key, value))
}

// ---------- filenames ----------

// LongName returns a string of n repeated characters, useful for edge-case filenames.
func LongName(ch byte, n int) string {
	return strings.Repeat(string(ch), n)
}

// MakeStandardCorpus populates a corpus with the full set of test cases
// matching the original gen_test_corpus.sh.
func MakeStandardCorpus(t *testing.T, dir string) *Corpus {
	c := NewCorpus(t, dir)
	isRoot := os.Getuid() == 0

	// ── Regular files ──────────────────────────────────────

	c.CreateFile(t, "files/empty", nil)
	c.CreateFile(t, "files/tiny_2b", []byte("hi"))
	c.CreateFile(t, "files/small_100b", []byte(strings.Repeat(".", 100)))
	c.CreateFile(t, "files/just_under_block", []byte(strings.Repeat("A", 4095)))
	c.CreateRandomFile(t, "files/exact_block", 4096)
	c.CreateRandomFile(t, "files/two_blocks", 4096*2)
	c.CreateRandomFile(t, "files/ten_blocks", 4096*10)
	c.CreateRandomFile(t, "files/large_256k", 256*1024)
	c.CreateZeroFile(t, "files/all_zeros", 4096*4)
	c.CreatePatternFile(t, "files/byte_pattern", 16)

	// ── Permissions ────────────────────────────────────────

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

	// ── Directories ────────────────────────────────────────

	c.CreateDir(t, "dirs/empty_dir")
	c.CreateDir(t, "dirs/a/b/c/d/e/f")
	c.CreateFile(t, "dirs/a/b/c/d/e/f/deep_file", []byte("deep"))
	c.CreateDir(t, "dirs/many_entries")
	for i := 1; i <= 200; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/many_entries/file_%04d", i),
			[]byte(fmt.Sprintf("entry_%d", i)))
	}
	c.CreateDir(t, "dirs/restricted")
	c.Chmod(t, "dirs/restricted", 0500)
	c.CreateDir(t, "dirs/sticky_dir")
	c.Chmod(t, "dirs/sticky_dir", 01777)

	// ── Symbolic links ─────────────────────────────────────

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

	// ── Hard links ─────────────────────────────────────────

	c.CreateFile(t, "hardlinks/original", []byte("shared content"))
	c.CreateHardlink(t, "hardlinks/link1", "hardlinks/original")
	c.CreateHardlink(t, "hardlinks/link2", "hardlinks/original")
	c.CreateDir(t, "hardlinks/subdir")
	c.CreateHardlink(t, "hardlinks/subdir/link3", "hardlinks/original")

	// ── Special files (root only) ──────────────────────────

	if isRoot {
		c.CreateFIFO(t, "special/fifo")
		c.CreateCharDev(t, "special/chardev", 1, 3)
		c.CreateBlockDev(t, "special/blkdev", 1, 0)
		c.CreateFile(t, "special/other_uid", []byte("other_owner"))
		c.Chown(t, "special/other_uid", 1000, 1000)
		c.CreateFile(t, "special/root_owned", []byte("root_only"))
		c.Chown(t, "special/root_owned", 0, 0)
		c.Chmod(t, "special/root_owned", 0600)
	}

	// ── Extended attributes ────────────────────────────────

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

	if isRoot {
		c.CreateFile(t, "xattrs/security_attr", []byte("security xattr\n"))
		c.SetXattr(t, "xattrs/security_attr", "security.test", []byte("sec_value"))

		c.CreateFile(t, "xattrs/trusted_attr", []byte("trusted xattr\n"))
		c.SetXattr(t, "xattrs/trusted_attr", "trusted.test", []byte("trusted_value"))
	}

	// ── Filenames with edge cases ──────────────────────────

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
