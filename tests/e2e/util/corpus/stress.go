package corpus

import (
	"fmt"
	mathrand "math/rand"
	"strings"
	"testing"
)

const stressSeed = 20260806

// MakeStress builds a large, deliberately awkward tree from a fixed seed.
//
// It is a superset of MakeStandard: that tree enumerates the cases a
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
func MakeStress(t testing.TB, dir string) {
	t.Helper()
	c := makeStandard(t, dir)
	rng := mathrand.New(mathrand.NewSource(stressSeed))

	stressDeepTree(t, c, rng)
	stressWideDirs(t, c)
	stressSparse(t, c, rng)
	stressSpecial(t, c, rng)
	stressLinks(t, c, rng)
	stressXattrs(t, c, rng)
	stressNames(t, c)
	stressRawNames(t, c)
	stressDirentPacking(t, c)
	stressSizes(t, c)
	stressInodeWidth(t, c)
	stressSecurity(t, c)
}

// stressSecurity covers the attribute namespaces a container image actually
// carries and that user.* does not reach: POSIX ACLs, which EROFS gives their
// own xattr name index, plus the capability and SELinux labels that live under
// security.*.
func stressSecurity(t testing.TB, c *Corpus) {
	c.CreateDir(t, "security")

	for i := range 20 {
		name := fmt.Sprintf("security/acl_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.setACL(t, name, minimalACL(uint32(1000+i)), false)
	}

	// Default ACLs only apply to directories and are stored separately from the
	// access ACL, so a directory carrying both holds two distinct attributes.
	for i := range 10 {
		name := fmt.Sprintf("security/acl_dir_%02d", i)
		c.CreateDir(t, name)
		c.setACL(t, name, minimalACL(uint32(2000+i)), false)
		c.setACL(t, name, minimalACL(uint32(3000+i)), true)
	}

	// An ACL long enough to spill out of the inline xattr area. The kernel
	// requires entries in tag order with named users ascending by id, so the
	// extra users go between user_obj and group_obj rather than on the end.
	big := []aclEntry{{Tag: aclUserObj, Perm: 6, ID: aclUndefined}}

	for i := range 60 {
		big = append(big, aclEntry{Tag: aclUser, Perm: 4, ID: uint32(5000 + i)})
	}

	big = append(big,
		aclEntry{Tag: aclGroupObj, Perm: 4, ID: aclUndefined},
		aclEntry{Tag: aclMask, Perm: 6, ID: aclUndefined},
		aclEntry{Tag: aclOther, Perm: 4, ID: aclUndefined},
	)

	c.CreateFile(t, "security/acl_many_entries", []byte("x"))
	c.setACL(t, "security/acl_many_entries", big, false)

	for i := range 20 {
		name := fmt.Sprintf("security/caps_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.Chmod(t, name, 0o755)
		c.SetFileCaps(t, name, uint32(1<<(i%32)), 0)
	}

	for i := range 20 {
		name := fmt.Sprintf("security/selinux_%02d", i)
		c.CreateFile(t, name, []byte(name))

		c.SetXattr(t, name, "security.selinux",
			[]byte(fmt.Sprintf("system_u:object_r:container_file_t:s0:c%d\x00", i)))
	}
}

// stressInodeWidth targets the compact/extended inode decision, which is the
// densest cluster of encoding branches in the builder. An EROFS compact inode
// stores i_size in 32 bits and mtime in 32 bits with no nanoseconds, so a
// timestamp past 2038 has to be promoted to the 64-byte extended form (files
// past 4GiB are in the Huge corpus). fsstress reaches these through setattr;
// here they are stated directly.
func stressInodeWidth(t testing.TB, c *Corpus) {
	c.CreateDir(t, "inode")

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
		c.setTimes(t, name, spec.sec, spec.nsec)
	}

	// A link count wider than a byte. The builder writes every inode with more
	// than one link in the extended form, whose i_nlink is 32 bits; the compact
	// form's 16-bit slot holds i_nb instead.
	c.CreateFile(t, "inode/many_links", []byte("shared"))
	c.CreateDir(t, "inode/links")

	for i := range 300 {
		c.CreateHardlink(t, fmt.Sprintf("inode/links/l%04d", i), "inode/many_links")
	}

	// Hardlinks to something other than a regular file: fsstress links any
	// non-directory, and the builder has to keep the type with the shared inode.
	c.CreateFIFO(t, "inode/fifo_orig")
	c.CreateHardlink(t, "inode/fifo_link", "inode/fifo_orig")
	c.CreateUnixSocket(t, "inode/sock_orig")
	c.CreateHardlink(t, "inode/sock_link", "inode/sock_orig")

	c.CreateCharDev(t, "inode/chr_orig", 1, 3)
	c.CreateHardlink(t, "inode/chr_link", "inode/chr_orig")

	// Symlink targets up to PATH_MAX. 4064 is the last size that still rides
	// inline behind a compact inode (EROFS_BLOCK_SIZE minus the 32-byte header);
	// anything above it has to fall back to a block of its own, so the sizes
	// straddling that boundary are the ones worth having.
	for _, n := range []int{1, 255, 256, 1023, 1024, 4032, 4064, 4065, 4090, 4095} {
		c.CreateSymlink(t, fmt.Sprintf("inode/symlink_target_%04d", n), strings.Repeat("t", n))
	}
}

// stressDeepTree nests to 13 levels, past anything the standard corpus reaches,
// and drops a file at every level so lookup has to walk the whole chain.
func stressDeepTree(t testing.TB, c *Corpus, rng *mathrand.Rand) {
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

// stressWideDirs spans many EROFS directory blocks: a 4KiB block holds about
// 270 entries with three-byte names (a 12-byte dirent plus the name) and 15
// with 255-byte ones, so these cross the boundary repeatedly, at a different
// entry for each name length.
func stressWideDirs(t testing.TB, c *Corpus) {
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
	}
}

// stressSparse is the dimension the standard corpus barely covers: holes that
// start and end at every interesting offset relative to the 4KiB block and the
// chunk size.
func stressSparse(t testing.TB, c *Corpus, rng *mathrand.Rand) {
	offsets := []int64{0, 1, 4095, 4096, 4097, 8191, 65535, 65536, 1 << 20}
	for i, off := range offsets {
		size := off + int64(1+rng.Intn(9000))

		c.CreateSparseFile(t, fmt.Sprintf("sparse/hole_at_%d", i), size, map[int64][]byte{
			off: []byte("DATA"),
		})
	}

	// Data islands separated by holes, so a single read spans hole-data-hole.
	for i := range 40 {
		writes := map[int64][]byte{}

		for j := range 1 + rng.Intn(6) {
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
func stressSpecial(t testing.TB, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "special")

	for i := range 60 {
		c.CreateFIFO(t, fmt.Sprintf("special/fifo_%02d", i))
	}

	for i := range 40 {
		c.CreateUnixSocket(t, fmt.Sprintf("special/sock_%02d", i))
	}

	// Sweep major/minor past 8 bits so the rdev encoding has to widen.
	for i := range 60 {
		major := uint32(rng.Intn(4096))
		minor := uint32(rng.Intn(1 << 20))
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%02d", i), major, minor)
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%02d", i), major, minor)
	}
}

// stressLinks builds hardlink groups of varying size plus symlink chains and
// loops, which is where nlink accounting and path resolution tend to break.
func stressLinks(t testing.TB, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "links")

	for group := range 20 {
		target := fmt.Sprintf("links/target_%02d", group)
		c.CreateRandomFile(t, target, 1+rng.Intn(4096))

		for n := range 1 + rng.Intn(8) {
			c.CreateHardlink(t, fmt.Sprintf("links/hard_%02d_%02d", group, n), target)
		}
	}

	// A chain long enough to approach, but not exceed, the kernel's 40-link limit.
	for i := range 30 {
		c.CreateSymlink(t, fmt.Sprintf("links/chain_%02d", i), fmt.Sprintf("chain_%02d", i+1))
	}

	c.CreateFile(t, "links/chain_30", []byte("chain end"))

	for i := range 20 {
		c.CreateSymlink(t, fmt.Sprintf("links/dangling_%02d", i), fmt.Sprintf("missing_%02d", i))
	}

	// An absolute target, relative to the corpus root as the image will be
	// mounted rather than to where the corpus happens to be staged, so the
	// tree does not change with its location.
	c.CreateSymlink(t, "links/abs", "/links/chain_30")
}

// stressXattrs pushes past the inline xattr body of an EROFS inode, where the
// builder has to spill into the shared xattr area.
//
// Sizes stay well under 4KiB per inode because the corpus is staged on ext4,
// which keeps all of an inode's attributes in a single block. That is still far
// more than the EROFS inline body holds, so the spill path is exercised.
func stressXattrs(t testing.TB, c *Corpus, rng *mathrand.Rand) {
	c.CreateDir(t, "xattr")

	for i := range 60 {
		name := fmt.Sprintf("xattr/f_%02d", i)
		c.CreateRandomFile(t, name, 1+rng.Intn(1024))

		count := 1 + i%8
		for j := range count {
			c.SetXattr(t, name,
				fmt.Sprintf("user.a%02d", j),
				[]byte(strings.Repeat("v", 1+rng.Intn(256))))
		}
	}

	// Many files sharing one identical attribute exercises deduplication.
	shared := []byte(strings.Repeat("shared", 100))

	for i := range 40 {
		name := fmt.Sprintf("xattr/shared_%02d", i)
		c.CreateFile(t, name, []byte{byte(i)})
		c.SetXattr(t, name, "user.common", shared)
	}

	c.CreateFile(t, "xattr/maxname", []byte("x"))
	c.SetXattr(t, "xattr/maxname", "user."+strings.Repeat("n", 250), []byte("v"))
	c.CreateFile(t, "xattr/bigvalue", []byte("x"))
	c.SetXattr(t, "xattr/bigvalue", "user.big", []byte(strings.Repeat("V", 3000)))

	// One inode carrying many small attributes. EROFS counts the inline xattr
	// area in 4-byte units, so the count rather than the byte total is what is
	// under test here. The staging filesystem caps an inode at 4 KiB of
	// attributes, which is what bounds this at 120.
	c.CreateFile(t, "xattr/many", []byte("x"))

	for i := range 120 {
		c.SetXattr(t, "xattr/many", fmt.Sprintf("user.m%03d", i), []byte{byte(i)})
	}
}

// stressNames covers the full 1..255 byte range plus the byte sequences that
// tend to be mishandled between the builder and the dirent encoder.
func stressNames(t testing.TB, c *Corpus) {
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
func stressRawNames(t testing.TB, c *Corpus) {
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
func stressDirentPacking(t testing.TB, c *Corpus) {
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
			c.CreateFile(t, fmt.Sprintf("%s/%s%04d", dir, strings.Repeat("p", nameLen-4), i), nil)
			used += direntSize + nameLen
			i++
		}
	}

	// A single 255-byte name in a block of its own, and a block filled with
	// them: 12+255 per entry means 15 entries fill 4005 of 4096 bytes, so the
	// sixteenth spills into a second block.
	c.CreateDir(t, "packing/maxname")

	for i := range 16 {
		c.CreateFile(t, fmt.Sprintf("packing/maxname/%s%03d", strings.Repeat("m", 252), i), nil)
	}

	// Names differing only in their last bytes. The kernel binary-searches
	// dirents by byte comparison, so a shared 250-byte prefix makes every probe
	// compare the full name.
	c.CreateDir(t, "packing/shared_prefix")
	prefix := strings.Repeat("s", 250)

	for i := range 400 {
		c.CreateFile(t, fmt.Sprintf("packing/shared_prefix/%s%04d", prefix, i), nil)
	}

	c.CreateDir(t, "packing/empty")
	c.CreateDir(t, "packing/single")
	c.CreateFile(t, "packing/single/only", []byte("only"))
}

// stressSizes brackets every chunk-size boundary the build matrix uses.
func stressSizes(t testing.TB, c *Corpus) {
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
}
