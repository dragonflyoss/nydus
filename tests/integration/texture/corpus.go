// Package texture provides helpers for generating an NydusFS filesystem test
// corpus.
//
// The Corpus type follows a builder pattern similar to nydus
// smoke/tests/tool/layer.go and creates real files on disk to exercise the
// `nydus build` and `nydus fuse` code paths.
package texture

import (
	"crypto/rand"
	"fmt"
	"io"
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

// CreateLargeFile fills a file with sizeMB megabytes of random data.
func (c *Corpus) CreateLargeFile(t *testing.T, name string, size int) {
	require.NoError(t, os.MkdirAll(filepath.Dir(c.path(name)), 0755))
	f, err := os.Create(c.path(name))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})

	_, err = io.CopyN(f, rand.Reader, int64(size)<<20)
	require.NoError(t, err)
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
func (c *Corpus) Chmod(t *testing.T, name string, mode os.FileMode) {
	require.NoError(t, os.Chmod(c.path(name), mode))
}

// Chown sets uid and gid (requires root).
func (c *Corpus) Chown(t *testing.T, name string, uid, gid int) {
	require.NoError(t, os.Lchown(c.path(name), uid, gid))
}

// SetXattr sets an extended attribute.
func (c *Corpus) SetXattr(t *testing.T, name, key string, value []byte) {
	require.NoError(t, xattr.Set(c.path(name), key, value))
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
	largeFileCount := GetEnvAsInt("NYDUSFS_PERF_LARGE_FILE_COUNT", 8)
	largeFileSize := GetEnvAsInt("NYDUSFS_PERF_LARGE_FILE_SIZE", 64*1024*1024)
	mediumFileCount := GetEnvAsInt("NYDUSFS_PERF_MEDIUM_FILE_COUNT", 256)
	mediumFileSize := GetEnvAsInt("NYDUSFS_PERF_MEDIUM_FILE", 1024*1024)
	smallFileCount := GetEnvAsInt("NYDUSFS_PERF_SMALL_FILE_COUNT", 10000)
	readdirDirs := GetEnvAsInt("NYDUSFS_PERF_READDIR_DIRS", 128)
	readdirFilesPerDir := GetEnvAsInt("NYDUSFS_PERF_READDIR_FILES_PER_DIR", 256)

	for i := range largeFileCount {
		c.CreateLargeFile(t, fmt.Sprintf("large/file_%d.bin", i), largeFileSize)
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
}

// GetEnvAsInt reads an environment variable as an integer, returning a default value if the variable is
// not set or cannot be parsed.
func GetEnvAsInt(key string, defaultValue int) int {
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
