package corpus

import (
	"fmt"
	"strings"
	"testing"
)

// MakeStandard populates dir with the standard tree: every file size, name
// and metadata case the readers must reproduce.
func MakeStandard(t testing.TB, dir string) {
	t.Helper()
	makeStandard(t, dir)
}

func makeStandard(t testing.TB, dir string) *Corpus {
	t.Helper()
	c := New(t, dir)

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

	c.createPatternFile(t, "files/byte_pattern", 16)

	// Permissions.
	c.CreateFile(t, "perms/r_only", []byte("readable"))
	c.Chmod(t, "perms/r_only", 0o444)
	c.CreateFile(t, "perms/r_x", []byte("executable"))
	c.Chmod(t, "perms/r_x", 0o555)
	c.CreateFile(t, "perms/rwx", []byte("all perms"))
	c.Chmod(t, "perms/rwx", 0o777)
	c.CreateFile(t, "perms/no_perm", []byte("no perms"))
	c.Chmod(t, "perms/no_perm", 0o000)
	c.CreateFile(t, "perms/setuid", []byte("setuid"))
	c.Chmod(t, "perms/setuid", 0o4755)
	c.CreateFile(t, "perms/setgid", []byte("setgid"))
	c.Chmod(t, "perms/setgid", 0o2755)
	c.CreateFile(t, "perms/sticky", []byte("sticky"))
	c.Chmod(t, "perms/sticky", 0o1755)
	c.CreateFile(t, "perms/suid_sgid", []byte("setuid+setgid"))
	c.Chmod(t, "perms/suid_sgid", 0o6755)

	// Owned by another user so an unprivileged reader falls through to the
	// "other" permission bits rather than the owner's.
	c.CreateFile(t, "perms/other_owner_r", []byte("other readable"))
	c.Chown(t, "perms/other_owner_r", 4000, 4000)
	c.Chmod(t, "perms/other_owner_r", 0o444)
	c.CreateFile(t, "perms/other_owner_none", []byte("other unreadable"))
	c.Chown(t, "perms/other_owner_none", 4000, 4000)
	c.Chmod(t, "perms/other_owner_none", 0o600)

	// A directory an unprivileged user may traverse but not list, and one it
	// may list but not traverse.
	c.CreateDir(t, "perms/x_only_dir")
	c.CreateFile(t, "perms/x_only_dir/hidden", []byte("reachable by name"))
	c.Chown(t, "perms/x_only_dir", 4000, 4000)
	c.Chmod(t, "perms/x_only_dir", 0o711)
	c.CreateDir(t, "perms/r_only_dir")
	c.CreateFile(t, "perms/r_only_dir/listed", []byte("listed but unreachable"))
	c.Chown(t, "perms/r_only_dir", 4000, 4000)
	c.Chmod(t, "perms/r_only_dir", 0o444)

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
	c.Chmod(t, "dirs/restricted", 0o500)
	c.CreateDir(t, "dirs/sticky_dir")
	c.Chmod(t, "dirs/sticky_dir", 0o1777)

	// Symbolic links.
	c.CreateFile(t, "symlinks/target_file", []byte("target"))
	c.CreateSymlink(t, "symlinks/link_to_file", "target_file")
	c.CreateDir(t, "symlinks/target_dir")
	c.CreateFile(t, "symlinks/target_dir/inner", []byte("in_dir"))
	c.CreateSymlink(t, "symlinks/link_to_dir", "target_dir")
	c.CreateSymlink(t, "symlinks/relative_link", "../files/tiny_2b")
	longName := strings.Repeat("x", 200)
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

	for i := range 50 {
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
	c.Chmod(t, "special/root_owned", 0o600)

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
	c.SetXattr(t, "xattrs/user_long_name", "user."+strings.Repeat("x", 200), []byte("long_name_test"))

	c.CreateDir(t, "xattrs/dir_with_xattr")
	c.SetXattr(t, "xattrs/dir_with_xattr", "user.dirattr", []byte("dir_value"))

	c.CreateFile(t, "xattrs/empty_file_xattr", nil)
	c.SetXattr(t, "xattrs/empty_file_xattr", "user.on_empty", []byte("has_xattr"))

	c.CreateRandomFile(t, "xattrs/large_file_xattr", 4096*4)
	c.SetXattr(t, "xattrs/large_file_xattr", "user.on_large", []byte("large_file"))

	c.CreateFile(t, "xattrs/user_huge_ibody", []byte("huge xattr body\n"))

	for i := range 3 {
		value := strings.Repeat(string(rune('A'+i)), 900)
		c.SetXattr(t, "xattrs/user_huge_ibody", fmt.Sprintf("user.large_%02d", i), []byte(value))
	}

	c.CreateDir(t, "xattrs/dir_huge_ibody")

	for i := range 3 {
		value := strings.Repeat(string(rune('k'+i)), 850)
		c.SetXattr(t, "xattrs/dir_huge_ibody", fmt.Sprintf("user.dir_large_%02d", i), []byte(value))
	}

	c.CreateFile(t, "xattrs/security_attr", []byte("security xattr\n"))
	c.SetXattr(t, "xattrs/security_attr", "security.test", []byte("sec_value"))

	c.CreateFile(t, "xattrs/trusted_attr", []byte("trusted xattr\n"))
	c.SetXattr(t, "xattrs/trusted_attr", "trusted.test", []byte("trusted_value"))

	// Filenames with edge cases.
	c.CreateFile(t, "names/"+strings.Repeat("a", 250), []byte("long name"))
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
