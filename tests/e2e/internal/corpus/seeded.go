package corpus

import (
	"bytes"
	"fmt"
	"io/fs"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// SeededSeed seeds the deterministic corpus every golden image is built
// from. Changing it, or anything in this file, changes the golden trees.
const SeededSeed = 20260930

// Seeded stages a deterministic tree: content comes from a seeded
// generator and finish pins the timestamps of every entry.
type Seeded struct {
	*Corpus
	rng   *mathrand.Rand
	times map[string]unix.Timespec
}

func NewSeeded(t env.TB, dir string, seed int64) *Seeded {
	return &Seeded{
		Corpus: NewCorpus(t, dir),
		rng:    mathrand.New(mathrand.NewSource(seed)),
		times:  map[string]unix.Timespec{},
	}
}

var seededWords = strings.Fields("nydus erofs chunk blob meta bootstrap layer image overlay " +
	"whiteout hole sparse inode xattr dirent symlink device fifo socket hardlink compact " +
	"extended superblock digest zstd lz4 prefetch cache fuse mount export registry")

// Random returns n incompressible bytes.
func (c *Seeded) Random(n int) []byte {
	b := make([]byte, n)
	_, _ = c.rng.Read(b)
	return b
}

// Text returns n bytes of compressible, but not repetitive, text.
func (c *Seeded) Text(n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(seededWords[c.rng.Intn(len(seededWords))])
		if c.rng.Intn(12) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
	return b.Bytes()[:n]
}

func (c *Seeded) SetTime(name string, sec, nsec int64) {
	c.times[name] = unix.Timespec{Sec: sec, Nsec: nsec}
}

func (c *Seeded) lsetxattr(t env.TB, name, key string, value []byte) {
	require.NoError(t, unix.Lsetxattr(filepath.Join(c.Dir, name), key, value, 0), "%s: %s", name, key)
}

func (c *Seeded) socket(t env.TB, name string) {
	path := filepath.Join(c.Dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, unix.Mknod(path, unix.S_IFSOCK|0755, 0))
}

// Finish pins the timestamps of every entry: the explicit ones, then a
// default for the rest, which mostly carry whole seconds (a compact inode
// cannot hold nanoseconds of its own) with every fifth one extended by a
// nanosecond part. Hardlinks share their inode's timestamp.
func (c *Seeded) Finish(t env.TB) {
	t.Helper()
	var paths []string
	require.NoError(t, filepath.WalkDir(c.Dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == c.Dir {
			return err
		}
		rel, err := filepath.Rel(c.Dir, path)
		paths = append(paths, rel)
		return err
	}))

	done := map[uint64]bool{}
	set := func(rel string, ts unix.Timespec) {
		path := filepath.Join(c.Dir, rel)
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(path, &st))
		if done[st.Ino] {
			return
		}
		done[st.Ino] = true
		require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW), rel)
	}
	explicit := make([]string, 0, len(c.times))
	for rel := range c.times {
		explicit = append(explicit, rel)
	}
	sort.Strings(explicit)
	for _, rel := range explicit {
		set(rel, c.times[rel])
	}
	for i, rel := range paths {
		ts := unix.Timespec{Sec: 1_700_000_000 + int64(i)*61}
		if i%5 == 4 {
			ts.Nsec = int64(i) * 7_919_993 % 1_000_000_000
		}
		set(rel, ts)
	}
	set(".", unix.Timespec{Sec: 1_700_000_000})
}

// MakeSeeded stages the tree every single-layer image is built from.
func MakeSeeded(t env.TB, dir string) {
	t.Helper()
	c := NewSeeded(t, dir, SeededSeed)
	seededData(t, c)
	seededHoles(t, c)
	seededMetadata(t, c)
	seededLinks(t, c)
	seededXattrs(t, c)
	seededNames(t, c)
	seededDirs(t, c)
	seededSymlinks(t, c)
	seededSpecial(t, c)
	c.Finish(t)
}

// seededData covers file data: sizes against every block, pcluster and
// chunk boundary of the layouts, inline tails, content that compresses well,
// badly or to nothing, and content that deduplicates.
func seededData(t env.TB, c *Seeded) {
	// Full, one byte short and one byte over the 4KiB block, the 64KiB
	// chunk and pcluster, and the 1MiB, 2MiB and 8MiB chunks.
	for i, size := range []int{
		0, 1, 2, 511, 512, 513, 4095, 4096, 4097, 8191, 8192, 8193, 12289,
		65535, 65536, 65537, 131073, 1<<20 - 1, 1 << 20, 1<<20 + 1,
		2<<20 - 1, 2 << 20, 2<<20 + 1, 8<<20 + 4097,
	} {
		name := fmt.Sprintf("data/size/%08d", size)
		if i%2 == 0 {
			c.CreateFile(t, name, c.Random(size))
		} else {
			c.CreateFile(t, name, c.Text(size))
		}
	}

	// Tails EROFS may keep inline behind the inode. Whether one fits
	// depends on the inode form (32-byte compact, 64-byte extended) and its
	// xattrs, so every size is staged in each form.
	for _, size := range []int{31, 32, 33, 2048, 4000, 4031, 4032, 4033, 4063, 4064, 4065, 4095, 4096 + 4031, 4096 + 4065} {
		c.CreateFile(t, fmt.Sprintf("data/inline/compact_%05d", size), c.Random(size))
		extended := fmt.Sprintf("data/inline/extended_%05d", size)
		c.CreateFile(t, extended, c.Random(size))
		c.Chown(t, extended, 70000, 70000)
		withXattr := fmt.Sprintf("data/inline/xattr_%05d", size)
		c.CreateFile(t, withXattr, c.Random(size))
		c.SetXattr(t, withXattr, "user.inline", bytes.Repeat([]byte{'x'}, 200))
	}

	// Written zeros: whole chunks of them are stored as holes.
	for _, size := range []int{4095, 4096, 65537, 2<<20 + 1} {
		c.CreateFile(t, fmt.Sprintf("data/content/zeros_%08d", size), make([]byte, size))
	}
	// A chunk that is zero but for its first or last byte is data.
	for _, at := range []int{0, 4095, 4096, 65535, 2<<20 - 1, 2 << 20, 4<<20 + 2} {
		data := make([]byte, 4<<20+3)
		data[at] = 0xa5
		c.CreateFile(t, fmt.Sprintf("data/content/lone_byte_%08d", at), data)
	}
	pattern := make([]byte, 3<<20+5)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	c.CreateFile(t, "data/content/pattern", pattern)
	c.CreateFile(t, "data/content/text", c.Text(1<<20+17))
	c.CreateFile(t, "data/content/random", c.Random(128<<10))
	barely := c.Random(256 << 10)
	for i := 0; i < len(barely); i += 16 {
		barely[i] = 0
	}
	c.CreateFile(t, "data/content/barely_compressible", barely)
	// Zero blocks inside data chunks, so no chunk is a hole.
	mixed := make([]byte, 1<<20)
	for off := 0; off < len(mixed); off += 8192 {
		copy(mixed[off:off+4096], c.Random(4096))
	}
	c.CreateFile(t, "data/content/mixed_blocks", mixed)

	shared := c.Random(2<<20 + 8193)
	c.CreateFile(t, "data/dedup/orig", shared)
	c.CreateFile(t, "data/dedup/copy", shared)
	c.CreateFile(t, "data/dedup/prefix", append(append([]byte{}, shared[:1<<20]...), c.Random(1<<20+5)...))
	c.CreateFile(t, "data/dedup/suffix", append(c.Random(64<<10), shared[64<<10:]...))
	c.CreateFile(t, "data/dedup/repeated", bytes.Repeat(c.Random(64<<10), 24))
	small := c.Text(5000)
	for i := 0; i < 8; i++ {
		c.CreateFile(t, fmt.Sprintf("data/dedup/small_%d", i), small)
	}
}

// seededHoles covers sparse files: holes that start, end and span each
// block, pcluster and chunk boundary, all-hole files, alternating runs and
// written zeros next to real holes.
func seededHoles(t env.TB, c *Seeded) {
	const block = 4096
	const chunk = 2 << 20

	// Nothing but a size, including a partial last block or chunk.
	for _, size := range []int64{1, block - 1, block, block + 1, 65536, 65537, chunk, chunk + 1, 9 << 20} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/empty/%08d", size), size, nil)
	}
	// A leading hole, then 16 bytes of data ending the file, the data
	// starting just before, on and just after each boundary.
	for _, off := range []int64{1, block - 1, block, block + 1, 65535, 65536, 65537, 1<<20 - 8, 1 << 20, chunk - 1, chunk, chunk + 1, 3*chunk - 8} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/leading/%08d", off), off+16, map[int64][]byte{off: c.Random(16)})
	}
	// Data from offset zero, then a trailing hole such as truncate leaves.
	for _, n := range []int{1, block - 1, block, block + 1, 65536, chunk - 1, chunk, chunk + 1} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/trailing/%08d", n), 6<<20, map[int64][]byte{0: c.Random(n)})
	}
	// A dozen bytes straddling a boundary, holes on both sides.
	for _, at := range []int64{block, 2 * block, 65536, 1 << 20, chunk, 2 * chunk} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/straddle/%08d", at), 3*chunk, map[int64][]byte{at - 6: c.Random(12)})
	}
	// Holes of one block, one 64KiB unit and several chunks between data.
	c.CreateSparseFile(t, "holes/gap/one_block", 3*block, map[int64][]byte{
		0: c.Random(block), 2 * block: c.Random(block),
	})
	c.CreateSparseFile(t, "holes/gap/one_64k", 3*65536, map[int64][]byte{
		0: c.Random(65536), 2 * 65536: c.Random(65536),
	})
	c.CreateSparseFile(t, "holes/gap/chunks", 5*chunk+100, map[int64][]byte{
		0: c.Random(block), 4 * chunk: c.Random(block), 5 * chunk: c.Random(100),
	})
	// A partial block of data at the end of the file, after a long hole.
	c.CreateSparseFile(t, "holes/gap/partial_tail", chunk+2*block+100, map[int64][]byte{
		chunk + 2*block: c.Random(100),
	})
	// Alternating data and holes at block granularity in both phases (the
	// shape xfstests punch-alternating makes), per 64KiB, and per chunk.
	for phase := int64(0); phase < 2; phase++ {
		writes := map[int64][]byte{}
		for b := int64(0); b < 128; b++ {
			if b%2 == phase {
				writes[b*block] = c.Random(block)
			}
		}
		c.CreateSparseFile(t, fmt.Sprintf("holes/alternating/block_%d", phase), 128*block, writes)
	}
	writes := map[int64][]byte{}
	for i := int64(0); i < 32; i += 2 {
		writes[i*65536] = c.Text(65536)
	}
	c.CreateSparseFile(t, "holes/alternating/64k", 32*65536, writes)
	writes = map[int64][]byte{}
	for i := int64(0); i < 6; i += 2 {
		writes[i*chunk] = c.Random(block)
		writes[(i+1)*chunk-block] = c.Random(block)
	}
	c.CreateSparseFile(t, "holes/alternating/chunk", 6*chunk, writes)
	// Written zeros read the same as a hole.
	c.CreateFile(t, "holes/zeros/written", make([]byte, chunk+4097))
	c.CreateSparseFile(t, "holes/zeros/sparse", chunk+4097, nil)
	c.CreateSparseFile(t, "holes/zeros/written_chunk", 3*chunk, map[int64][]byte{
		0: c.Random(16), chunk: make([]byte, chunk), 3*chunk - 16: c.Random(16),
	})
	// Islands of random length at random distances.
	for i := 0; i < 8; i++ {
		writes := map[int64][]byte{}
		off := int64(c.rng.Intn(3 * block))
		for j := 0; j < 6; j++ {
			n := 1 + c.rng.Intn(20000)
			writes[off] = c.Random(n)
			off += int64(n) + int64(1+c.rng.Intn(600000))
		}
		c.CreateSparseFile(t, fmt.Sprintf("holes/islands/%02d", i), off+int64(c.rng.Intn(block)), writes)
	}
	// Files past 4GiB live in the Huge corpus: through readers that cannot
	// seek over holes they cost gigabytes of zeros per pass.
}

// seededMetadata covers inode attributes: permission and special mode
// bits, owners either side of the 16-bit compact limit, and timestamps at the
// epoch, with nanoseconds, and past 2038 and 2106.
func seededMetadata(t env.TB, c *Seeded) {
	for _, mode := range []uint32{0, 01, 07, 070, 0400, 0444, 0600, 0640, 0644, 0664, 0700, 0711, 0755, 0777, 01000, 01777, 02000, 02755, 04000, 04755, 06755, 07777} {
		name := fmt.Sprintf("meta/mode/file_%04o", mode)
		c.CreateFile(t, name, []byte(name))
		c.Chmod(t, name, mode)
	}
	for _, mode := range []uint32{0, 0500, 0555, 0700, 0711, 0755, 0777, 01777, 02775, 03777, 07755} {
		name := fmt.Sprintf("meta/mode/dir_%04o", mode)
		c.CreateFile(t, name+"/inner", []byte(name))
		c.Chmod(t, name, mode)
	}

	for _, id := range [][2]int{
		{0, 0}, {1, 2}, {1000, 1000}, {65534, 65534}, {65535, 65535}, {65535, 65536},
		{65536, 65535}, {65536, 65536}, {100000, 200000}, {2147483647, 2147483647},
		{2147483648, 1}, {1, 2147483648}, {4294967294, 4294967294},
	} {
		name := fmt.Sprintf("meta/owner/file_%d_%d", id[0], id[1])
		c.CreateFile(t, name, []byte(name))
		c.Chown(t, name, id[0], id[1])
	}
	c.CreateFile(t, "meta/owner/dir_70000/inner", nil)
	c.Chown(t, "meta/owner/dir_70000", 70000, 70001)
	c.CreateSymlink(t, "meta/owner/symlink", "file_0_0")
	c.Chown(t, "meta/owner/symlink", 12345, 54321)

	for i, ts := range [][2]int64{
		{0, 0}, {0, 1}, {1, 0}, {1, 999999999}, {1234567890, 0}, {1234567890, 123456789},
		{1<<31 - 1, 0}, {1 << 31, 0}, {1<<32 - 1, 0}, {1 << 32, 0}, {1<<32 + 1, 500000000},
		{1 << 33, 999999999},
	} {
		name := fmt.Sprintf("meta/mtime/file_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.SetTime(name, ts[0], ts[1])
	}
	c.CreateFile(t, "meta/mtime/dir_nsec/inner", nil)
	c.SetTime("meta/mtime/dir_nsec", 1600000000, 987654321)
	c.CreateDir(t, "meta/mtime/dir_future")
	c.SetTime("meta/mtime/dir_future", 1<<33, 0)
	c.CreateSymlink(t, "meta/mtime/symlink_nsec", "file_00")
	c.SetTime("meta/mtime/symlink_nsec", 1500000000, 1)
}

// seededLinks covers hardlink groups: within and across directories,
// large, of empty, sparse and attribute-laden files, and of every
// non-directory type.
func seededLinks(t env.TB, c *Seeded) {
	c.CreateFile(t, "links/pair/a", c.Text(3000))
	c.CreateHardlink(t, "links/pair/b", "links/pair/a")
	c.CreateFile(t, "links/cross/x/f", c.Random(10000))
	c.CreateHardlink(t, "links/cross/y/f", "links/cross/x/f")
	c.CreateHardlink(t, "links/cross/z/deeper/f", "links/cross/x/f")
	c.CreateFile(t, "links/many/target", []byte("many"))
	for i := 0; i < 100; i++ {
		c.CreateHardlink(t, fmt.Sprintf("links/many/l%03d", i), "links/many/target")
	}
	c.CreateFile(t, "links/empty/a", nil)
	c.CreateHardlink(t, "links/empty/b", "links/empty/a")
	c.CreateSparseFile(t, "links/sparse/a", 3<<20, map[int64][]byte{1 << 20: c.Random(100)})
	c.CreateHardlink(t, "links/sparse/b", "links/sparse/a")
	c.CreateFile(t, "links/meta/a", c.Random(5000))
	c.Chmod(t, "links/meta/a", 04750)
	c.Chown(t, "links/meta/a", 70000, 70001)
	c.SetXattr(t, "links/meta/a", "user.link", []byte("shared by the group"))
	c.SetTime("links/meta/a", 1650000000, 424242424)
	c.CreateHardlink(t, "links/meta/b", "links/meta/a")
	c.CreateHardlink(t, "links/meta/c", "links/meta/a")
	c.CreateFile(t, "links/big/a", c.Text(3<<20))
	c.CreateHardlink(t, "links/big/b", "links/big/a")

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

// seededXattrs covers extended attributes: empty, binary and long
// values, long names, many per inode, identical ones shared across inodes,
// every name prefix EROFS indexes, and xattrs on every file type.
func seededXattrs(t env.TB, c *Seeded) {
	c.CreateFile(t, "xattr/small", []byte("x"))
	c.SetXattr(t, "xattr/small", "user.a", []byte("1"))
	c.CreateFile(t, "xattr/empty_value", []byte("x"))
	c.lsetxattr(t, "xattr/empty_value", "user.empty", nil)
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	c.CreateFile(t, "xattr/binary_value", []byte("x"))
	c.SetXattr(t, "xattr/binary_value", "user.binary", binary)
	c.CreateFile(t, "xattr/long_value", []byte("x"))
	c.SetXattr(t, "xattr/long_value", "user.long", c.Text(3000))
	c.CreateFile(t, "xattr/long_name", []byte("x"))
	c.SetXattr(t, "xattr/long_name", "user."+LongName('n', 250), []byte("v"))
	c.CreateFile(t, "xattr/many", []byte("x"))
	for i := 0; i < 100; i++ {
		c.SetXattr(t, "xattr/many", fmt.Sprintf("user.m%03d", i), c.Random(1+i%8))
	}
	// Entries are padded to 4 bytes, so name and value lengths cover every
	// remainder.
	c.CreateFile(t, "xattr/alignment", []byte("x"))
	for n := 1; n <= 4; n++ {
		for v := 0; v <= 4; v++ {
			c.SetXattr(t, "xattr/alignment", fmt.Sprintf("user.%s%d", LongName('a', n), v), bytes.Repeat([]byte{'v'}, v))
		}
	}
	// Identical xattrs on many inodes, which EROFS may share.
	shared := c.Text(600)
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("xattr/shared/f%02d", i)
		c.CreateFile(t, name, []byte{byte(i)})
		c.SetXattr(t, name, "user.shared", shared)
		c.SetXattr(t, name, "user.common", []byte("c"))
		c.SetXattr(t, name, "user.own", []byte(name))
	}
	c.CreateFile(t, "xattr/prefixes", []byte("x"))
	c.SetXattr(t, "xattr/prefixes", "user.p", []byte("user"))
	c.SetXattr(t, "xattr/prefixes", "trusted.p", []byte("trusted"))
	c.SetXattr(t, "xattr/prefixes", "security.p", []byte("security"))
	c.CreateFile(t, "xattr/selinux", []byte("x"))
	c.SetXattr(t, "xattr/selinux", "security.selinux", []byte("system_u:object_r:bin_t:s0\x00"))
	c.CreateFile(t, "xattr/capability", []byte("x"))
	c.Chmod(t, "xattr/capability", 0755)
	c.SetFileCaps(t, "xattr/capability", 1<<13, 0)
	c.CreateFile(t, "xattr/acl", []byte("x"))
	c.SetACL(t, "xattr/acl", MinimalACL(1000), false)
	c.CreateFile(t, "xattr/acl_dir/inner", []byte("x"))
	c.SetACL(t, "xattr/acl_dir", MinimalACL(2000), false)
	c.SetACL(t, "xattr/acl_dir", MinimalACL(3000), true)

	// Every file type, through the namespaces each one accepts.
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

// seededNames covers file names: every length up to 255 bytes, special
// characters, bytes that are not UTF-8, and names that sort as prefixes.
func seededNames(t env.TB, c *Seeded) {
	for n := 1; n <= 255; n++ {
		c.CreateFile(t, "names/length/"+LongName('n', n), nil)
	}
	for i, name := range []string{
		" leading", "trailing ", "mid space", "tab\there", "new\nline", "quote'sq", `quote"dq`,
		`back\slash`, "star*", "question?", "brack[et]", "dollar$", "semi;colon", "pct%d",
		"colon:name", "utf8-中文", "utf8-🙂", "combining-e\u0301", ".hidden", "...", "..dots",
		"dot.", "-dash", "~tilde", "Case", "case", "CASE", "=eq", "#hash", "@at", "{brace}",
	} {
		c.CreateFile(t, "names/special/"+name, []byte{byte(i)})
	}
	for _, name := range []string{
		"latin1_caf\xe9", "cp1252_\x93quoted\x94", "gbk_\xd6\xd0\xce\xc4", "lone_surrogate_\xed\xa0\x80",
		"overlong_\xc0\xaf", "truncated_\xe4\xb8", "ctrl_\x01\x02\x1f\x7f", "\xff", "\xfe\xff",
		"collide_\xfe", "collide_\xff", "collide_\xfe\xfe",
	} {
		c.CreateFile(t, "names/raw/"+name, []byte(name))
	}
	for _, name := range []string{"pre", "pre0", "preA", "prea", "pre_", "pre~", "pre\x7f", "pre\x80", "pre\xff"} {
		c.CreateFile(t, "names/prefix/"+name, []byte(name))
	}
}

// seededDirs covers directories: empty, deeply nested, spanning many
// blocks with short, mixed and 255-byte names, entries that end exactly on,
// just short of and just past a 4KiB directory block, and one of each type.
func seededDirs(t env.TB, c *Seeded) {
	c.CreateDir(t, "dirs/empty")
	c.CreateDir(t, "dirs/empty_chain/a/b/c/d")
	path := "dirs/deep"
	for depth := 1; depth <= 40; depth++ {
		path = fmt.Sprintf("%s/d%02d", path, depth)
		c.CreateFile(t, path+"/leaf", []byte(path))
	}
	for i := 0; i < 1000; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_short/%03d", i), nil)
	}
	for i := 0; i < 400; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_mixed/%0*d", 1+i%255, i), nil)
	}
	for i := 0; i < 100; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_long/%s%03d", LongName('l', 252), i), nil)
	}
	for i := 0; i < 300; i++ {
		c.CreateDir(t, fmt.Sprintf("dirs/subdirs/s%03d", i))
	}

	// Each dirent is a 12-byte header plus its name, and "." and ".."
	// come first.
	const block, dirent, nameLen = 4096, 12, 30
	for _, delta := range []int{-1, 0, 1} {
		dir := fmt.Sprintf("dirs/packing/exact_%+d", delta)
		c.CreateDir(t, dir)
		used := 2*dirent + 1 + 2
		for i := 0; used+dirent+nameLen <= block+delta; i++ {
			c.CreateFile(t, fmt.Sprintf("%s/%s%04d", dir, LongName('p', nameLen-4), i), nil)
			used += dirent + nameLen
		}
	}

	c.CreateFile(t, "dirs/types/file", []byte("file"))
	c.CreateDir(t, "dirs/types/dir")
	c.CreateSymlink(t, "dirs/types/symlink", "file")
	c.CreateFIFO(t, "dirs/types/fifo")
	c.CreateCharDev(t, "dirs/types/chr", 1, 7)
	c.CreateBlockDev(t, "dirs/types/blk", 7, 0)
	c.socket(t, "dirs/types/socket")
}

// seededSymlinks covers symlink targets of every length class up to
// PATH_MAX, around the inline limits, and unusual targets.
func seededSymlinks(t env.TB, c *Seeded) {
	for _, n := range []int{1, 2, 31, 32, 33, 255, 256, 1023, 1024, 2048, 4031, 4032, 4033, 4063, 4064, 4065, 4094, 4095} {
		c.CreateSymlink(t, fmt.Sprintf("symlinks/length_%04d", n), LongName('t', n))
	}
	for name, target := range map[string]string{
		"dangling": "missing/target",
		"absolute": "/etc/hostname",
		"dir":      "../dirs",
		"dot":      ".",
		"dotdot":   "..",
		"self":     "self",
		"raw":      "caf\xe9/\xff",
		"spaces":   "with space/and\nnewline",
		"chain_a":  "chain_b",
		"chain_b":  "chain_c",
		"chain_c":  "../data/size/00000001",
	} {
		c.CreateSymlink(t, "symlinks/"+name, target)
	}
}

// seededSpecial covers device, fifo and socket nodes, with device
// numbers past 8 bits up to the 12-bit major and 20-bit minor limits.
func seededSpecial(t env.TB, c *Seeded) {
	c.CreateFIFO(t, "special/fifo")
	c.CreateFIFO(t, "special/fifo_0600")
	c.Chmod(t, "special/fifo_0600", 0600)
	for _, dev := range [][2]uint32{{1, 3}, {4, 64}, {10, 200}, {136, 1}, {255, 255}, {256, 0}, {0, 256}, {259, 65536}, {4095, 1048575}} {
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%d_%d", dev[0], dev[1]), dev[0], dev[1])
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%d_%d", dev[0], dev[1]), dev[0], dev[1])
	}
	c.socket(t, "special/socket")
	c.socket(t, "special/socket_0700")
	c.Chmod(t, "special/socket_0700", 0700)
}

// MakeMergeLayers stages three layers whose overlay exercises every
// whiteout form, type changes in both directions, metadata overrides of files
// and directories, hardlink groups broken or removed by upper layers, and a
// name removed and re-added.
func MakeMergeLayers(t env.TB, dirs []string) {
	t.Helper()
	require.Len(t, dirs, 3)

	lower := NewSeeded(t, dirs[0], SeededSeed+1)
	shared := lower.Random(3<<20 + 17)
	lower.CreateFile(t, "keep/text", lower.Text(10000))
	lower.CreateFile(t, "keep/random", shared)
	lower.CreateSparseFile(t, "keep/sparse", 5<<20, map[int64][]byte{2<<20 - 8: lower.Random(16)})
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

	middle := NewSeeded(t, dirs[1], SeededSeed+2)
	middle.CreateFile(t, "keep_copy/random", shared)
	middle.CreateFile(t, "change/.wh.removed", nil)
	middle.CreateFile(t, "change/.wh.removed_dir", nil)
	middle.CreateFile(t, "change/.wh.never_existed", nil)
	middle.CreateFile(t, "change/opaque/.wh..wh..opq", nil)
	middle.CreateFile(t, "change/opaque/new", []byte("new"))
	middle.CreateFile(t, "change/replaced", middle.Random(70000))
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

	upper := NewSeeded(t, dirs[2], SeededSeed+3)
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
