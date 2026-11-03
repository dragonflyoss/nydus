package corpus

// The compatibility corpus is what every release builds the compatibility images of
// (tests/e2e/compatibility). The images are committed to git, so it covers the
// on-disk encodings the Seeded corpus does at a fraction of the size. The
// costliest layout for data is erofs-none: it stores each 2MiB chunk that
// holds any data raw, and a file's last chunk up to its size, holes
// included. So data sits in small files or in the last, short chunk of a
// large sparse one. Files past 4GiB are in MakeCompatibilityHuge.
//
// The compatibility trees are recorded in each version's manifest, so changing
// this file only changes the images of releases still to come.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

const compatibilitySeed = 20261019

// MakeCompatibility stages the tree every single-layer compatibility image is built from.
func MakeCompatibility(t testing.TB, dir string) {
	t.Helper()
	c := newSeeded(t, dir, compatibilitySeed)
	compatibilityData(t, c)
	compatibilityHoles(t, c)
	compatibilityMetadata(t, c)
	compatibilityLinks(t, c)
	compatibilityXattrs(t, c)
	compatibilityNames(t, c)
	compatibilityDirs(t, c)
	compatibilitySymlinks(t, c)
	compatibilitySpecial(t, c)
	c.Finish(t)
}

// compatibilityData covers file data: sizes against the 4KiB block and the 64KiB
// chunk and pcluster, inline tails behind each inode form, content that
// compresses well, badly or to nothing, and content that deduplicates.
func compatibilityData(t testing.TB, c *seeded) {
	// Incompressible data where a size spills just past a block or a
	// pcluster; text elsewhere keeps the compressed images small.
	for _, size := range []int{0, 1, 4095, 4096, 4097, 8193, 65536, 65537} {
		name := fmt.Sprintf("data/size/%08d", size)

		if size == 1 || size == 4097 || size == 65537 {
			c.CreateFile(t, name, c.Random(size))
		} else {
			c.CreateFile(t, name, c.Text(size))
		}
	}

	// Sizes just past the 2MiB and 8MiB chunks, with data only in the
	// short last chunk.
	c.CreateSparseFile(t, "data/size/02097153", 2<<20+1, map[int64][]byte{2 << 20: c.Text(1)})
	c.CreateSparseFile(t, "data/size/08392705", 8<<20+4097, map[int64][]byte{8<<20 + 1: c.Text(4096)})

	// Tails EROFS may keep inline behind a 32-byte compact or 64-byte
	// extended inode, with and without xattrs taking up the block.
	for _, size := range []int{33, 4031, 4032, 4033, 4063, 4064, 4065, 4096 + 4031, 4096 + 4065} {
		c.CreateFile(t, fmt.Sprintf("data/inline/compact_%05d", size), c.Random(size))
		extended := fmt.Sprintf("data/inline/extended_%05d", size)
		c.CreateFile(t, extended, c.Text(size))
		c.Chown(t, extended, 70000, 70000)
		withXattr := fmt.Sprintf("data/inline/xattr_%05d", size)
		c.CreateFile(t, withXattr, c.Text(size))
		c.SetXattr(t, withXattr, "user.inline", bytes.Repeat([]byte{'x'}, 200))
	}

	// Written zeros, whole chunks of which are stored as holes.
	for _, size := range []int{4096, 65537, 2<<20 + 1} {
		c.CreateFile(t, fmt.Sprintf("data/content/zeros_%08d", size), make([]byte, size))
	}

	// A block that is zero but for its first or last byte is data.
	for _, at := range []int{0, 4095, 4096, 8194} {
		data := make([]byte, 8195)
		data[at] = 0xa5
		c.CreateFile(t, fmt.Sprintf("data/content/lone_byte_%05d", at), data)
	}

	pattern := make([]byte, 12<<10+5)
	for i := range pattern {
		pattern[i] = byte(i)
	}

	c.CreateFile(t, "data/content/pattern", pattern)
	c.CreateFile(t, "data/content/text", c.Text(8000))
	// Zero blocks inside data chunks, so no chunk is a hole.
	mixed := make([]byte, 32<<10)
	for off := 0; off < len(mixed); off += 8192 {
		copy(mixed[off:off+4096], c.Random(4096))
	}

	c.CreateFile(t, "data/content/mixed_blocks", mixed)

	shared := c.Random(8<<10 + 5)
	c.CreateFile(t, "data/dedup/orig", shared)
	c.CreateFile(t, "data/dedup/copy", shared)
	c.CreateFile(t, "data/dedup/prefix", append(append([]byte{}, shared[:4<<10]...), c.Random(4099)...))
	c.CreateFile(t, "data/dedup/suffix", append(c.Random(4096), shared[4<<10:]...))
	c.CreateFile(t, "data/dedup/repeated", bytes.Repeat(c.Random(4096), 4))
	small := c.Text(5000)

	for i := range 2 {
		c.CreateFile(t, fmt.Sprintf("data/dedup/small_%d", i), small)
	}
}

// compatibilityHoles covers sparse files: holes that start, end and span block,
// 64KiB and chunk boundaries, all-hole files, alternating runs, and written
// zeros next to real holes.
func compatibilityHoles(t testing.TB, c *seeded) {
	const block = 4096

	const chunk = 2 << 20

	// Nothing but a size.
	for _, size := range []int64{1, block - 1, block, block + 1, 65537, chunk, chunk + 1, 9 << 20} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/empty/%08d", size), size, nil)
	}

	// A leading hole, then 16 bytes of data ending the file.
	for _, off := range []int64{1, block - 1, block, block + 1, 65536, chunk, chunk + 1, 8 << 20} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/leading/%08d", off), off+16, map[int64][]byte{off: c.Random(16)})
	}

	// Data from offset zero, then a trailing hole such as truncate leaves.
	for _, n := range []int{1, block - 1, block, block + 1} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/trailing/%08d", n), int64(n)+2*block, map[int64][]byte{0: c.Text(n)})
	}

	// A dozen bytes straddling a boundary, holes on both sides.
	for _, at := range []int64{block, 65536} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/straddle/%08d", at), at+2*block, map[int64][]byte{at - 6: c.Random(12)})
	}

	// Holes of one block and one 64KiB unit between data, and a partial
	// block of data after a hole of a whole chunk.
	c.CreateSparseFile(t, "holes/gap/one_block", 3*block, map[int64][]byte{
		0: c.Text(block), 2 * block: c.Text(block),
	})

	c.CreateSparseFile(t, "holes/gap/one_64k", 2*65536+block, map[int64][]byte{
		65536 - block: c.Text(block), 2 * 65536: c.Text(block),
	})

	c.CreateSparseFile(t, "holes/gap/partial_tail", chunk+2*block+100, map[int64][]byte{
		chunk + 2*block: c.Random(100),
	})
	// Alternating data and holes at block granularity in both phases.
	for phase := range int64(2) {
		writes := map[int64][]byte{}

		for b := range int64(8) {
			if b%2 == phase {
				writes[b*block] = c.Text(block)
			}
		}

		c.CreateSparseFile(t, fmt.Sprintf("holes/alternating/block_%d", phase), 8*block, writes)
	}

	// Written zeros read the same as a hole.
	c.CreateFile(t, "holes/zeros/written", make([]byte, 2*block+1))
	c.CreateSparseFile(t, "holes/zeros/sparse", 2*block+1, nil)

	c.CreateSparseFile(t, "holes/zeros/written_block", 3*block, map[int64][]byte{
		0: c.Random(16), block: make([]byte, block), 3*block - 16: c.Random(16),
	})
	// Islands of random length at random distances.
	for i := range 2 {
		writes := map[int64][]byte{}
		off := int64(c.rng.Intn(3 * block))

		for range 4 {
			n := 1 + c.rng.Intn(1500)
			writes[off] = c.Random(n)
			off += int64(n) + int64(1+c.rng.Intn(6000))
		}

		c.CreateSparseFile(t, fmt.Sprintf("holes/islands/%02d", i), off+int64(c.rng.Intn(block)), writes)
	}
}

// MakeCompatibilityHuge stages the files past 4GiB, apart from the compatibility corpus:
// a layout indexes every 4KiB block or chunk of a file, holes included, so
// they cost megabytes in the layouts with 4KiB chunks and in the compressed
// EROFS ones, and compatibility images carry them only in the layouts with large
// chunks.
func MakeCompatibilityHuge(t testing.TB, dir string) {
	t.Helper()
	c := newSeeded(t, dir, compatibilitySeed+4)
	// u32::MAX is the largest size a compact inode holds; past it an inode
	// needs the extended form and file offsets pass 32 bits. Data straddles
	// 4GiB, which is also a block, 64KiB, 2MiB and 8MiB boundary.
	c.CreateSparseFile(t, "huge/4g_minus_1", 4<<30-1, nil)

	c.CreateSparseFile(t, "huge/4g_plus_4097", 4<<30+4097, map[int64][]byte{
		4<<30 - 8: c.Random(16), 4<<30 + 4097 - 16: c.Random(16),
	})

	c.Finish(t)
}

// compatibilityMetadata covers inode attributes: permission and special mode
// bits, owners either side of the 16-bit compact limit, and timestamps at the
// epoch, with nanoseconds, and past 2038 and 2106. The files are empty: in
// the uncompressed EROFS layouts any data takes a whole block.
func compatibilityMetadata(t testing.TB, c *seeded) {
	for _, mode := range []uint32{0, 0o644, 0o755, 0o1777, 0o2755, 0o4755, 0o7777} {
		name := fmt.Sprintf("meta/mode/file_%04o", mode)
		c.CreateFile(t, name, nil)
		c.Chmod(t, name, mode)
	}

	for _, mode := range []uint32{0, 0o555, 0o1777, 0o7755} {
		name := fmt.Sprintf("meta/mode/dir_%04o", mode)
		c.CreateFile(t, name+"/inner", nil)
		c.Chmod(t, name, mode)
	}

	for _, id := range [][2]int{
		{0, 0}, {65535, 65535}, {65535, 65536}, {65536, 65535},
		{2147483648, 1}, {4294967294, 4294967294},
	} {
		name := fmt.Sprintf("meta/owner/file_%d_%d", id[0], id[1])
		c.CreateFile(t, name, nil)
		c.Chown(t, name, id[0], id[1])
	}

	c.CreateFile(t, "meta/owner/dir_70000/inner", nil)
	c.Chown(t, "meta/owner/dir_70000", 70000, 70001)
	c.CreateSymlink(t, "meta/owner/symlink", "file_0_0")
	c.Chown(t, "meta/owner/symlink", 12345, 54321)

	for i, ts := range [][2]int64{
		{0, 0}, {1, 999999999}, {1<<31 - 1, 0}, {1 << 31, 0}, {1<<32 - 1, 0}, {1<<32 + 1, 500000000}, {1 << 33, 999999999},
	} {
		name := fmt.Sprintf("meta/mtime/file_%02d", i)
		c.CreateFile(t, name, nil)
		c.SetTime(name, ts[0], ts[1])
	}

	c.CreateFile(t, "meta/mtime/dir_nsec/inner", nil)
	c.SetTime("meta/mtime/dir_nsec", 1600000000, 987654321)
	c.CreateDir(t, "meta/mtime/dir_future")
	c.SetTime("meta/mtime/dir_future", 1<<33, 0)
	c.CreateSymlink(t, "meta/mtime/symlink_nsec", "file_00")
	c.SetTime("meta/mtime/symlink_nsec", 1500000000, 1)
}

// compatibilityLinks covers hardlink groups: within and across directories,
// large, of empty, sparse and attribute-laden files, and of every
// non-directory type.
func compatibilityLinks(t testing.TB, c *seeded) {
	c.CreateFile(t, "links/pair/a", c.Text(3000))
	c.CreateHardlink(t, "links/pair/b", "links/pair/a")
	c.CreateFile(t, "links/cross/x/f", c.Random(1000))
	c.CreateHardlink(t, "links/cross/y/f", "links/cross/x/f")
	c.CreateHardlink(t, "links/cross/z/deeper/f", "links/cross/x/f")
	c.CreateFile(t, "links/many/target", []byte("many"))

	for i := range 10 {
		c.CreateHardlink(t, fmt.Sprintf("links/many/l%02d", i), "links/many/target")
	}

	c.CreateFile(t, "links/empty/a", nil)
	c.CreateHardlink(t, "links/empty/b", "links/empty/a")
	c.CreateSparseFile(t, "links/sparse/a", 3*4096, map[int64][]byte{4096: c.Random(100)})
	c.CreateHardlink(t, "links/sparse/b", "links/sparse/a")
	c.CreateFile(t, "links/meta/a", c.Random(500))
	c.Chmod(t, "links/meta/a", 0o4750)
	c.Chown(t, "links/meta/a", 70000, 70001)
	c.SetXattr(t, "links/meta/a", "user.link", []byte("shared by the group"))
	c.SetTime("links/meta/a", 1650000000, 424242424)
	c.CreateHardlink(t, "links/meta/b", "links/meta/a")
	c.CreateHardlink(t, "links/meta/c", "links/meta/a")

	c.CreateFIFO(t, "links/special/fifo_a")
	c.CreateHardlink(t, "links/special/fifo_b", "links/special/fifo_a")
	c.CreateCharDev(t, "links/special/chr_a", 10, 200)
	c.CreateHardlink(t, "links/special/chr_b", "links/special/chr_a")
	c.CreateBlockDev(t, "links/special/blk_a", 8, 16)
	c.CreateHardlink(t, "links/special/blk_b", "links/special/blk_a")
	c.CreateUnixSocket(t, "links/special/sock_a")
	c.CreateHardlink(t, "links/special/sock_b", "links/special/sock_a")
	c.CreateSymlink(t, "links/special/symlink_a", "../pair/a")
	c.CreateHardlink(t, "links/special/symlink_b", "links/special/symlink_a")
}

// compatibilityXattrs covers extended attributes: empty, binary and long values,
// long names, many per inode, identical ones shared across inodes, every
// name prefix EROFS indexes, ACLs, capabilities, and xattrs on every file
// type. Only xattr/small has data next to its xattrs.
func compatibilityXattrs(t testing.TB, c *seeded) {
	c.CreateFile(t, "xattr/small", []byte("x"))
	c.SetXattr(t, "xattr/small", "user.a", []byte("1"))
	c.CreateFile(t, "xattr/empty_value", nil)
	c.lsetxattr(t, "xattr/empty_value", "user.empty", nil)

	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}

	c.CreateFile(t, "xattr/binary_value", nil)
	c.SetXattr(t, "xattr/binary_value", "user.binary", binary)
	c.CreateFile(t, "xattr/long_value", nil)
	c.SetXattr(t, "xattr/long_value", "user.long", c.Text(3000))
	c.CreateFile(t, "xattr/long_name", nil)
	c.SetXattr(t, "xattr/long_name", "user."+strings.Repeat("n", 250), []byte("v"))
	c.CreateFile(t, "xattr/many", nil)

	for i := range 24 {
		c.SetXattr(t, "xattr/many", fmt.Sprintf("user.m%03d", i), c.Random(1+i%8))
	}

	// Entries are padded to 4 bytes, so name and value lengths cover every
	// remainder.
	c.CreateFile(t, "xattr/alignment", nil)

	for n := 1; n <= 4; n++ {
		for v := 0; v <= 4; v++ {
			c.SetXattr(t, "xattr/alignment", fmt.Sprintf("user.%s%d", strings.Repeat("a", n), v), bytes.Repeat([]byte{'v'}, v))
		}
	}

	// Identical xattrs on several inodes, which EROFS may share.
	shared := c.Text(600)

	for i := range 4 {
		name := fmt.Sprintf("xattr/shared/f%02d", i)
		c.CreateFile(t, name, nil)
		c.SetXattr(t, name, "user.shared", shared)
		c.SetXattr(t, name, "user.common", []byte("c"))
		c.SetXattr(t, name, "user.own", []byte(name))
	}

	c.CreateFile(t, "xattr/prefixes", nil)
	c.SetXattr(t, "xattr/prefixes", "user.p", []byte("user"))
	c.SetXattr(t, "xattr/prefixes", "trusted.p", []byte("trusted"))
	c.SetXattr(t, "xattr/prefixes", "security.p", []byte("security"))
	c.CreateFile(t, "xattr/selinux", nil)
	c.SetXattr(t, "xattr/selinux", "security.selinux", []byte("system_u:object_r:bin_t:s0\x00"))
	c.CreateFile(t, "xattr/capability", nil)
	c.Chmod(t, "xattr/capability", 0o755)
	c.SetFileCaps(t, "xattr/capability", 1<<13, 0)
	c.CreateFile(t, "xattr/acl", nil)
	c.setACL(t, "xattr/acl", minimalACL(1000), false)
	c.CreateFile(t, "xattr/acl_dir/inner", nil)
	c.setACL(t, "xattr/acl_dir", minimalACL(2000), false)
	c.setACL(t, "xattr/acl_dir", minimalACL(3000), true)

	c.CreateFile(t, "xattr/types/dir/inner", nil)
	c.SetXattr(t, "xattr/types/dir", "user.dir", []byte("dir"))
	c.SetXattr(t, "xattr/types/dir", "trusted.dir", []byte("dir"))
	c.CreateSymlink(t, "xattr/types/symlink", "../small")
	c.lsetxattr(t, "xattr/types/symlink", "trusted.symlink", []byte("symlink"))
	c.CreateFIFO(t, "xattr/types/fifo")
	c.lsetxattr(t, "xattr/types/fifo", "trusted.fifo", []byte("fifo"))
	c.CreateCharDev(t, "xattr/types/chr", 1, 5)
	c.lsetxattr(t, "xattr/types/chr", "trusted.chr", []byte("chr"))
	c.CreateUnixSocket(t, "xattr/types/socket")
	c.lsetxattr(t, "xattr/types/socket", "trusted.socket", []byte("socket"))
}

// compatibilityNames covers file names: lengths around every power of two up to
// 255 bytes, special characters, bytes that are not UTF-8, and names that
// sort as prefixes. The files are empty, as in compatibilityMetadata.
func compatibilityNames(t testing.TB, c *seeded) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 200, 251, 252, 253, 254, 255} {
		c.CreateFile(t, "names/length/"+strings.Repeat("n", n), nil)
	}

	for _, name := range []string{
		" leading", "trailing ", "mid space", "tab\there", "new\nline", "quote'sq", `quote"dq`,
		`back\slash`, "star*", "question?", "brack[et]", "dollar$", "colon:name", "utf8-中文",
		"utf8-🙂", "combining-e\u0301", ".hidden", "...", "..dots", "-dash", "Case", "case",
	} {
		c.CreateFile(t, "names/special/"+name, nil)
	}

	for _, name := range []string{
		"latin1_caf\xe9", "gbk_\xd6\xd0\xce\xc4", "lone_surrogate_\xed\xa0\x80", "overlong_\xc0\xaf",
		"truncated_\xe4\xb8", "ctrl_\x01\x02\x1f\x7f", "\xff", "collide_\xfe", "collide_\xff",
	} {
		c.CreateFile(t, "names/raw/"+name, nil)
	}

	for _, name := range []string{"pre", "pre0", "preA", "prea", "pre_", "pre~", "pre\x7f", "pre\x80", "pre\xff"} {
		c.CreateFile(t, "names/prefix/"+name, nil)
	}
}

// compatibilityDirs covers directories: empty, deeply nested, spanning several
// blocks with short and 255-byte names, entries that end exactly on, just
// short of and just past a 4KiB directory block, and one of each type.
func compatibilityDirs(t testing.TB, c *seeded) {
	c.CreateDir(t, "dirs/empty")
	c.CreateDir(t, "dirs/empty_chain/a/b/c/d")
	path := "dirs/deep"

	for depth := 1; depth <= 40; depth++ {
		path = fmt.Sprintf("%s/d%02d", path, depth)
	}

	c.CreateFile(t, path+"/leaf", []byte(path))
	// Short names fill a directory block with about 270 entries, 255-byte
	// ones with 15.
	for i := range 300 {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_short/%03d", i), nil)
	}

	for i := range 20 {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_long/%s%03d", strings.Repeat("l", 252), i), nil)
	}

	for i := range 20 {
		c.CreateDir(t, fmt.Sprintf("dirs/subdirs/s%02d", i))
	}

	const block, dirent = 4096, 12

	for _, delta := range []int{-1, 0, 1} {
		dir := fmt.Sprintf("dirs/packing/exact_%+d", delta)
		c.CreateDir(t, dir)

		left := block + delta - (2*dirent + 1 + 2)
		for i := 0; left > dirent+255; i++ {
			c.CreateFile(t, fmt.Sprintf("%s/%s%04d", dir, strings.Repeat("p", 116), i), nil)
			left -= dirent + 120
		}

		c.CreateFile(t, dir+"/"+strings.Repeat("q", left-dirent), nil)
	}

	c.CreateFile(t, "dirs/types/file", []byte("file"))
	c.CreateDir(t, "dirs/types/dir")
	c.CreateSymlink(t, "dirs/types/symlink", "file")
	c.CreateFIFO(t, "dirs/types/fifo")
	c.CreateCharDev(t, "dirs/types/chr", 1, 7)
	c.CreateBlockDev(t, "dirs/types/blk", 7, 0)
	c.CreateUnixSocket(t, "dirs/types/socket")
}

// compatibilitySymlinks covers symlink targets around the inline limits up to
// PATH_MAX, and unusual targets.
func compatibilitySymlinks(t testing.TB, c *seeded) {
	for _, n := range []int{1, 31, 32, 33, 255, 256, 1024, 4031, 4032, 4033, 4063, 4064, 4065, 4095} {
		c.CreateSymlink(t, fmt.Sprintf("symlinks/length_%04d", n), strings.Repeat("t", n))
	}

	for _, link := range [][2]string{
		{"dangling", "missing/target"},
		{"absolute", "/etc/hostname"},
		{"dir", "../dirs"},
		{"dotdot", ".."},
		{"self", "self"},
		{"raw", "caf\xe9/\xff"},
		{"spaces", "with space/and\nnewline"},
		{"chain_a", "chain_b"},
		{"chain_b", "../data/size/00000001"},
	} {
		c.CreateSymlink(t, "symlinks/"+link[0], link[1])
	}
}

// compatibilitySpecial covers device, fifo and socket nodes, with device numbers
// past 8 bits up to the 12-bit major and 20-bit minor limits.
func compatibilitySpecial(t testing.TB, c *seeded) {
	c.CreateFIFO(t, "special/fifo")
	c.CreateFIFO(t, "special/fifo_0600")
	c.Chmod(t, "special/fifo_0600", 0o600)

	for _, dev := range [][2]uint32{{1, 3}, {255, 255}, {256, 0}, {0, 256}, {259, 65536}, {4095, 1048575}} {
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%d_%d", dev[0], dev[1]), dev[0], dev[1])
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%d_%d", dev[0], dev[1]), dev[0], dev[1])
	}

	c.CreateUnixSocket(t, "special/socket")
	c.CreateUnixSocket(t, "special/socket_0700")
	c.Chmod(t, "special/socket_0700", 0o700)
}

// MakeCompatibilityLayers stages the three layers of the merged compatibility images:
// every whiteout form, type changes in both directions, metadata overrides of
// files and directories, hardlink groups broken or removed by upper layers,
// and a name removed and re-added.
func MakeCompatibilityLayers(t testing.TB, dirs []string) {
	t.Helper()
	makeLayers(t, dirs, compatibilitySeed, 8000, 3<<20, (*seeded).Text)
}
