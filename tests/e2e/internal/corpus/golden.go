package corpus

// The golden corpus is what every release builds the golden images of
// (tests/e2e/golden). The images are committed to git, so it covers the
// on-disk encodings the Seeded corpus does at a fraction of the size. The
// costliest layout for data is erofs-none: it stores each 2MiB chunk that
// holds any data raw, and a file's last chunk up to its size, holes
// included. So data sits in small files or in the last, short chunk of a
// large sparse one. Files past 4GiB are in MakeGoldenHuge.
//
// The golden trees are recorded in each version's manifest, so changing
// this file only changes the images of releases still to come.

import (
	"bytes"
	"fmt"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// GoldenSeed seeds the golden corpus, its files past 4GiB and its merge
// layers.
const GoldenSeed = 20261019

// MakeGolden stages the tree every single-layer golden image is built from.
func MakeGolden(t env.TB, dir string) {
	t.Helper()
	c := NewSeeded(t, dir, GoldenSeed)
	goldenData(t, c)
	goldenHoles(t, c)
	goldenMetadata(t, c)
	goldenLinks(t, c)
	goldenXattrs(t, c)
	goldenNames(t, c)
	goldenDirs(t, c)
	goldenSymlinks(t, c)
	goldenSpecial(t, c)
	c.Finish(t)
}

// goldenData covers file data: sizes against the 4KiB block and the 64KiB
// chunk and pcluster, inline tails behind each inode form, content that
// compresses well, badly or to nothing, and content that deduplicates.
func goldenData(t env.TB, c *Seeded) {
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
	for i := 0; i < 2; i++ {
		c.CreateFile(t, fmt.Sprintf("data/dedup/small_%d", i), small)
	}
}

// goldenHoles covers sparse files: holes that start, end and span block,
// 64KiB and chunk boundaries, all-hole files, alternating runs, and written
// zeros next to real holes.
func goldenHoles(t env.TB, c *Seeded) {
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
	for phase := int64(0); phase < 2; phase++ {
		writes := map[int64][]byte{}
		for b := int64(0); b < 8; b++ {
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
	for i := 0; i < 2; i++ {
		writes := map[int64][]byte{}
		off := int64(c.rng.Intn(3 * block))
		for j := 0; j < 4; j++ {
			n := 1 + c.rng.Intn(1500)
			writes[off] = c.Random(n)
			off += int64(n) + int64(1+c.rng.Intn(6000))
		}
		c.CreateSparseFile(t, fmt.Sprintf("holes/islands/%02d", i), off+int64(c.rng.Intn(block)), writes)
	}
}

// MakeGoldenHuge stages the files past 4GiB, apart from the golden corpus:
// a layout indexes every 4KiB block or chunk of a file, holes included, so
// they cost megabytes in the layouts with 4KiB chunks and in the compressed
// EROFS ones, and golden images carry them only in the layouts with large
// chunks.
func MakeGoldenHuge(t env.TB, dir string) {
	t.Helper()
	const g4 = int64(1) << 32
	c := NewSeeded(t, dir, GoldenSeed+4)
	// u32::MAX is the largest size a compact inode holds; past it an inode
	// needs the extended form and file offsets pass 32 bits. Data straddles
	// 4GiB, which is also a block, 64KiB, 2MiB and 8MiB boundary.
	c.CreateSparseFile(t, "huge/4g_minus_1", g4-1, nil)
	c.CreateSparseFile(t, "huge/4g_plus_4097", g4+4097, map[int64][]byte{
		g4 - 8: c.Random(16), g4 + 4097 - 16: c.Random(16),
	})
	c.Finish(t)
}

// goldenMetadata covers inode attributes: permission and special mode
// bits, owners either side of the 16-bit compact limit, and timestamps at the
// epoch, with nanoseconds, and past 2038 and 2106. The files are empty: in
// the uncompressed EROFS layouts any data takes a whole block.
func goldenMetadata(t env.TB, c *Seeded) {
	for _, mode := range []uint32{0, 0644, 0755, 01777, 02755, 04755, 07777} {
		name := fmt.Sprintf("meta/mode/file_%04o", mode)
		c.CreateFile(t, name, nil)
		c.Chmod(t, name, mode)
	}
	for _, mode := range []uint32{0, 0555, 01777, 07755} {
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

// goldenLinks covers hardlink groups: within and across directories,
// large, of empty, sparse and attribute-laden files, and of every
// non-directory type.
func goldenLinks(t env.TB, c *Seeded) {
	c.CreateFile(t, "links/pair/a", c.Text(3000))
	c.CreateHardlink(t, "links/pair/b", "links/pair/a")
	c.CreateFile(t, "links/cross/x/f", c.Random(1000))
	c.CreateHardlink(t, "links/cross/y/f", "links/cross/x/f")
	c.CreateHardlink(t, "links/cross/z/deeper/f", "links/cross/x/f")
	c.CreateFile(t, "links/many/target", []byte("many"))
	for i := 0; i < 10; i++ {
		c.CreateHardlink(t, fmt.Sprintf("links/many/l%02d", i), "links/many/target")
	}
	c.CreateFile(t, "links/empty/a", nil)
	c.CreateHardlink(t, "links/empty/b", "links/empty/a")
	c.CreateSparseFile(t, "links/sparse/a", 3*4096, map[int64][]byte{4096: c.Random(100)})
	c.CreateHardlink(t, "links/sparse/b", "links/sparse/a")
	c.CreateFile(t, "links/meta/a", c.Random(500))
	c.Chmod(t, "links/meta/a", 04750)
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
	c.socket(t, "links/special/sock_a")
	c.CreateHardlink(t, "links/special/sock_b", "links/special/sock_a")
	c.CreateSymlink(t, "links/special/symlink_a", "../pair/a")
	c.CreateHardlink(t, "links/special/symlink_b", "links/special/symlink_a")
}

// goldenXattrs covers extended attributes: empty, binary and long values,
// long names, many per inode, identical ones shared across inodes, every
// name prefix EROFS indexes, ACLs, capabilities, and xattrs on every file
// type. Only xattr/small has data next to its xattrs.
func goldenXattrs(t env.TB, c *Seeded) {
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
	c.SetXattr(t, "xattr/long_name", "user."+LongName('n', 250), []byte("v"))
	c.CreateFile(t, "xattr/many", nil)
	for i := 0; i < 24; i++ {
		c.SetXattr(t, "xattr/many", fmt.Sprintf("user.m%03d", i), c.Random(1+i%8))
	}
	// Entries are padded to 4 bytes, so name and value lengths cover every
	// remainder.
	c.CreateFile(t, "xattr/alignment", nil)
	for n := 1; n <= 4; n++ {
		for v := 0; v <= 4; v++ {
			c.SetXattr(t, "xattr/alignment", fmt.Sprintf("user.%s%d", LongName('a', n), v), bytes.Repeat([]byte{'v'}, v))
		}
	}
	// Identical xattrs on several inodes, which EROFS may share.
	shared := c.Text(600)
	for i := 0; i < 4; i++ {
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
	c.Chmod(t, "xattr/capability", 0755)
	c.SetFileCaps(t, "xattr/capability", 1<<13, 0)
	c.CreateFile(t, "xattr/acl", nil)
	c.SetACL(t, "xattr/acl", MinimalACL(1000), false)
	c.CreateFile(t, "xattr/acl_dir/inner", nil)
	c.SetACL(t, "xattr/acl_dir", MinimalACL(2000), false)
	c.SetACL(t, "xattr/acl_dir", MinimalACL(3000), true)

	c.CreateFile(t, "xattr/types/dir/inner", nil)
	c.SetXattr(t, "xattr/types/dir", "user.dir", []byte("dir"))
	c.SetXattr(t, "xattr/types/dir", "trusted.dir", []byte("dir"))
	c.CreateSymlink(t, "xattr/types/symlink", "../small")
	c.lsetxattr(t, "xattr/types/symlink", "trusted.symlink", []byte("symlink"))
	c.CreateFIFO(t, "xattr/types/fifo")
	c.lsetxattr(t, "xattr/types/fifo", "trusted.fifo", []byte("fifo"))
	c.CreateCharDev(t, "xattr/types/chr", 1, 5)
	c.lsetxattr(t, "xattr/types/chr", "trusted.chr", []byte("chr"))
	c.socket(t, "xattr/types/socket")
	c.lsetxattr(t, "xattr/types/socket", "trusted.socket", []byte("socket"))
}

// goldenNames covers file names: lengths around every power of two up to
// 255 bytes, special characters, bytes that are not UTF-8, and names that
// sort as prefixes. The files are empty, as in goldenMetadata.
func goldenNames(t env.TB, c *Seeded) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 200, 251, 252, 253, 254, 255} {
		c.CreateFile(t, "names/length/"+LongName('n', n), nil)
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

// goldenDirs covers directories: empty, deeply nested, spanning several
// blocks with short and 255-byte names, entries that end exactly on, just
// short of and just past a 4KiB directory block, and one of each type.
func goldenDirs(t env.TB, c *Seeded) {
	c.CreateDir(t, "dirs/empty")
	c.CreateDir(t, "dirs/empty_chain/a/b/c/d")
	path := "dirs/deep"
	for depth := 1; depth <= 40; depth++ {
		path = fmt.Sprintf("%s/d%02d", path, depth)
	}
	c.CreateFile(t, path+"/leaf", []byte(path))
	// Short names fill a directory block with about 270 entries, 255-byte
	// ones with 15.
	for i := 0; i < 300; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_short/%03d", i), nil)
	}
	for i := 0; i < 20; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_long/%s%03d", LongName('l', 252), i), nil)
	}
	for i := 0; i < 20; i++ {
		c.CreateDir(t, fmt.Sprintf("dirs/subdirs/s%02d", i))
	}

	// Each dirent is a 12-byte header plus its name, and "." and ".."
	// come first. The entries of each directory add up to one byte short
	// of, exactly and one byte past a 4KiB block, the last name taking up
	// the slack.
	const block, dirent = 4096, 12
	for _, delta := range []int{-1, 0, 1} {
		dir := fmt.Sprintf("dirs/packing/exact_%+d", delta)
		c.CreateDir(t, dir)
		left := block + delta - (2*dirent + 1 + 2)
		for i := 0; left > dirent+255; i++ {
			c.CreateFile(t, fmt.Sprintf("%s/%s%04d", dir, LongName('p', 116), i), nil)
			left -= dirent + 120
		}
		c.CreateFile(t, dir+"/"+LongName('q', left-dirent), nil)
	}

	c.CreateFile(t, "dirs/types/file", []byte("file"))
	c.CreateDir(t, "dirs/types/dir")
	c.CreateSymlink(t, "dirs/types/symlink", "file")
	c.CreateFIFO(t, "dirs/types/fifo")
	c.CreateCharDev(t, "dirs/types/chr", 1, 7)
	c.CreateBlockDev(t, "dirs/types/blk", 7, 0)
	c.socket(t, "dirs/types/socket")
}

// goldenSymlinks covers symlink targets around the inline limits up to
// PATH_MAX, and unusual targets.
func goldenSymlinks(t env.TB, c *Seeded) {
	for _, n := range []int{1, 31, 32, 33, 255, 256, 1024, 4031, 4032, 4033, 4063, 4064, 4065, 4095} {
		c.CreateSymlink(t, fmt.Sprintf("symlinks/length_%04d", n), LongName('t', n))
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

// goldenSpecial covers device, fifo and socket nodes, with device numbers
// past 8 bits up to the 12-bit major and 20-bit minor limits.
func goldenSpecial(t env.TB, c *Seeded) {
	c.CreateFIFO(t, "special/fifo")
	c.CreateFIFO(t, "special/fifo_0600")
	c.Chmod(t, "special/fifo_0600", 0600)
	for _, dev := range [][2]uint32{{1, 3}, {255, 255}, {256, 0}, {0, 256}, {259, 65536}, {4095, 1048575}} {
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%d_%d", dev[0], dev[1]), dev[0], dev[1])
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%d_%d", dev[0], dev[1]), dev[0], dev[1])
	}
	c.socket(t, "special/socket")
	c.socket(t, "special/socket_0700")
	c.Chmod(t, "special/socket_0700", 0700)
}

// MakeGoldenLayers stages the three layers of the merged golden images:
// every whiteout form, type changes in both directions, metadata overrides of
// files and directories, hardlink groups broken or removed by upper layers,
// and a name removed and re-added.
func MakeGoldenLayers(t env.TB, dirs []string) {
	t.Helper()
	require.Len(t, dirs, 3)

	lower := NewSeeded(t, dirs[0], GoldenSeed+1)
	shared := lower.Random(8000)
	lower.CreateFile(t, "keep/text", lower.Text(10000))
	lower.CreateFile(t, "keep/random", shared)
	lower.CreateSparseFile(t, "keep/sparse", 3<<20, map[int64][]byte{2<<20 - 8: lower.Random(16)})
	lower.CreateFile(t, "keep/xattr", []byte("x"))
	lower.SetXattr(t, "keep/xattr", "user.layer", []byte("lower"))
	lower.CreateSymlink(t, "keep/symlink", "text")
	lower.CreateFIFO(t, "keep/fifo")
	lower.CreateCharDev(t, "keep/chr", 1, 3)
	lower.CreateFile(t, "keep/owner", nil)
	lower.Chown(t, "keep/owner", 70000, 70000)
	lower.CreateFile(t, "change/replaced", lower.Text(5000))
	lower.CreateFile(t, "change/removed", []byte("removed"))
	lower.CreateFile(t, "change/removed_dir/a", nil)
	lower.CreateFile(t, "change/removed_dir/sub/b", nil)
	lower.CreateFile(t, "change/opaque/old", nil)
	lower.CreateFile(t, "change/opaque/old_sub/x", nil)
	lower.CreateFile(t, "change/file_to_dir", []byte("file"))
	lower.CreateFile(t, "change/dir_to_file/child", []byte("child"))
	lower.CreateFile(t, "change/file_to_symlink", []byte("file"))
	lower.CreateSymlink(t, "change/symlink_to_file", "replaced")
	lower.CreateFIFO(t, "change/fifo_to_file")
	lower.CreateFile(t, "change/readded", []byte("v1"))
	lower.CreateFile(t, "change/meta_file", []byte("lower"))
	lower.SetXattr(t, "change/meta_file", "user.a", []byte("lower"))
	lower.CreateFile(t, "change/meta_dir/lower_child", nil)
	lower.SetXattr(t, "change/meta_dir", "user.dir", []byte("lower"))
	lower.Chown(t, "change/meta_dir", 1000, 1000)
	lower.CreateFile(t, "links/a", lower.Text(4000))
	lower.CreateHardlink(t, "links/b", "links/a")
	lower.CreateHardlink(t, "links/c", "links/a")
	lower.CreateFile(t, "links/p", lower.Text(100))
	lower.CreateHardlink(t, "links/q", "links/p")
	lower.CreateFile(t, "links/whole/x", nil)
	lower.CreateHardlink(t, "links/whole/y", "links/whole/x")
	lower.Finish(t)

	middle := NewSeeded(t, dirs[1], GoldenSeed+2)
	middle.CreateFile(t, "keep_copy/random", shared)
	middle.CreateFile(t, "change/.wh.removed", nil)
	middle.CreateFile(t, "change/.wh.removed_dir", nil)
	middle.CreateFile(t, "change/.wh.never_existed", nil)
	middle.CreateFile(t, "change/opaque/.wh..wh..opq", nil)
	middle.CreateFile(t, "change/opaque/new", []byte("new"))
	middle.CreateFile(t, "change/replaced", middle.Text(70000))
	middle.Chmod(t, "change/replaced", 0600)
	middle.CreateFile(t, "change/file_to_dir/inner", []byte("inner"))
	middle.CreateFile(t, "change/dir_to_file", []byte("now a file"))
	middle.CreateSymlink(t, "change/file_to_symlink", "replaced")
	middle.CreateFile(t, "change/symlink_to_file", []byte("now a file"))
	middle.CreateFile(t, "change/fifo_to_file", []byte("now a file"))
	middle.CreateFile(t, "change/.wh.readded", nil)
	middle.CreateFile(t, "change/meta_file", []byte("middle"))
	middle.SetXattr(t, "change/meta_file", "user.b", []byte("middle"))
	middle.CreateFile(t, "change/meta_dir/middle_child", nil)
	middle.SetXattr(t, "change/meta_dir", "user.dir", []byte("middle"))
	middle.Chown(t, "change/meta_dir", 2000, 2000)
	middle.Chmod(t, "change/meta_dir", 0700)
	middle.CreateFile(t, "links/b", []byte("breaks the group"))
	middle.CreateFile(t, "links/.wh.q", nil)
	middle.CreateFile(t, "links/.wh.whole", nil)
	middle.CreateFile(t, "links/new_a", middle.Text(300))
	middle.CreateHardlink(t, "links/new_b", "links/new_a")
	middle.Finish(t)

	upper := NewSeeded(t, dirs[2], GoldenSeed+3)
	upper.CreateFile(t, "change/readded", []byte("v3"))
	upper.CreateFile(t, "change/.wh.file_to_dir", nil)
	upper.CreateFile(t, "change/opaque/.wh.new", nil)
	upper.CreateFile(t, "change/opaque/newest", nil)
	upper.CreateFile(t, "fresh/deep/er/file", upper.Text(2000))
	upper.CreateDir(t, "change/meta_dir")
	upper.SetXattr(t, "change/meta_dir", "user.dir", []byte("upper"))
	upper.SetTime("change/meta_dir", 1800000000, 123)
	upper.Finish(t)
}
