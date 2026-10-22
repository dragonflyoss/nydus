package tar

import (
	"archive/tar"
	"bytes"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// defaultSeedCount is how many archives TestRandomLayers generates unless
// NYDUS_E2E_TAR_SEEDS says otherwise.
const defaultSeedCount = 200

// nameComponents are the path components member names are built from.
var nameComponents = []string{
	"a", "b", "c", "dir", "file", "link", "x y", "ünïcödé", "..dots", "-dash",
	strings.Repeat("n", 120), "nl\nname", "bad\xffutf8", "tab\tname",
}

// memberXattrs are the extended attributes a member may carry.
var memberXattrs = [][2]string{
	{"user.a", "1"},
	{"user.bin", "\x00\x01\xff"},
	{"user.nl", "a\nb"},
	{"user.empty", ""},
	{"user.long", strings.Repeat("v", 3000)},
	{"trusted.t", "x"},
	{"security.selinux", "system_u:object_r:foo_t:s0\x00"},
}

// fileSizes are the file sizes bodies are drawn from, around the block
// and chunk boundaries.
var fileSizes = []int64{
	0, 1, 100, 511, 512, 513, 4095, 4096, 4097, 64<<10 - 1, 64 << 10, 64<<10 + 1,
	1<<20 - 1, 1 << 20, 1<<20 + 1, 2<<20 + 3,
}

// ustarFields are the header fields mutateLayer corrupts, as offset and
// length within the block.
var ustarFields = []struct {
	// name is the field's name in the USTAR header.
	name string

	// offset and length locate the field within the block.
	offset, length int
}{
	{"name", 0, 100}, {"mode", 100, 8}, {"uid", 108, 8}, {"gid", 116, 8},
	{"size", 124, 12}, {"mtime", 136, 12}, {"typeflag", 156, 1},
	{"linkname", 157, 100}, {"magic", 257, 6}, {"version", 263, 2},
	{"uname", 265, 32}, {"gname", 297, 32}, {"devmajor", 329, 8},
	{"devminor", 337, 8}, {"prefix", 345, 155},
}

// TestRandomLayers converts seeded random layers, member mixes no hand-written
// vector covers: overrides of every type by every type, links through
// symlinked parents, hardlinks through any of their names, whiteouts,
// setgid directories, xattrs, and file sizes around the chunk and block
// boundaries, in random header formats and blob layouts. A failing seed
// replays with -run 'TestRandomLayers/^seed-05$'.
func TestRandomLayers(t *testing.T) {
	util.SkipUnlessRoot(t, "the reference tree restores ownership and device nodes")
	t.Parallel()

	// Read the seed count from the environment.
	seedCount := defaultSeedCount
	if s := os.Getenv("NYDUS_E2E_TAR_SEEDS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			t.Fatalf("NYDUS_E2E_TAR_SEEDS=%q: want a positive count", s)
		}
		seedCount = n
	}

	// Check the share of valid layers in a cleanup, which runs once the
	// parallel seeds have, after this function returned. Rejections test
	// little, so the generator must keep producing valid layers.
	var converted, ran atomic.Int32
	t.Cleanup(func() {
		if !t.Failed() && converted.Load() < ran.Load()*2/3 {
			t.Errorf("only %d of %d random layers were valid", converted.Load(), ran.Load())
		}
	})

	// Convert one random layer per seed, in a random blob layout.
	layoutNames := slices.Sorted(maps.Keys(blobLayouts))
	for seed := range seedCount {
		t.Run(fmt.Sprintf("seed-%02d", seed), func(t *testing.T) {
			t.Parallel()
			ran.Add(1)

			// Pick the default layout or one of the named ones.
			rng := newSeededRand(uint64(seed))
			layout := blobLayout{}
			if i := rng.IntN(len(layoutNames) + 2); i < len(layoutNames) {
				layout = blobLayouts[layoutNames[i]]
				t.Logf("layout %s", layoutNames[i])
			}

			if checkConversion(t, randomLayer(rng, 8<<20), layout) {
				converted.Add(1)
			}
		})
	}
}

// TestMutatedLayers converts random layers with one header field corrupted
// and its checksum recomputed, or cut short, so the reader's validation
// paths meet the builder's: every mutant must convert to exactly what
// containerd applies, or be rejected without a crash.
func TestMutatedLayers(t *testing.T) {
	util.SkipUnlessRoot(t, "the reference tree restores ownership and device nodes")
	t.Parallel()

	// Convert the base layers; mutants of a layer containerd rejects anyway
	// test little.
	baseLayers := make([][]byte, 10)
	for i := range baseLayers {
		baseLayers[i] = randomLayer(newSeededRand(1000+uint64(i)), 64<<10)
		t.Run(fmt.Sprintf("base-%d", i), func(t *testing.T) {
			t.Parallel()
			assert.True(t, checkConversion(t, baseLayers[i], blobLayout{}), "base layer rejected")
		})
	}

	// Convert one mutant of a base layer per seed.
	for seed := range 150 {
		rng := newSeededRand(2000 + uint64(seed))
		data, name := mutateLayer(rng, baseLayers[seed%len(baseLayers)])
		t.Run(fmt.Sprintf("%03d-%s", seed, name), func(t *testing.T) {
			t.Parallel()
			checkConversion(t, data, blobLayout{})
		})
	}
}

// FuzzConversion runs checkConversion on arbitrary bytes. Without
// -fuzz it replays the seeds; with it, run as root:
// go test -run '^$' -fuzz FuzzConversion ./tar
func FuzzConversion(f *testing.F) {
	for i := range 4 {
		data := randomLayer(newSeededRand(3000+uint64(i)), 16<<10)
		f.Add(data)
		f.Add(data[:len(data)/2])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		util.SkipUnlessRoot(t, "the reference tree restores ownership and device nodes")
		checkConversion(t, data, blobLayout{})
	})
}

// newSeededRand returns a generator seeded by seed, the same stream for the
// same seed.
func newSeededRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, 0x6e79647573))
}

// pick returns a random element of s.
func pick[T any](rng *rand.Rand, s []T) T {
	return s[rng.IntN(len(s))]
}

// layerGenerator accumulates a random layer, tracking the tree containerd applies
// from it so that most members are valid: each lands in a directory, maybe
// through a symlink to one, and each hardlink names a file.
type layerGenerator struct {
	// rng drives every choice.
	rng *rand.Rand

	// tw writes the layer.
	tw *tar.Writer

	// kinds maps each applied path to 'd', 'f', or 'l' for a symlink.
	kinds map[string]byte

	// order holds the keys of kinds in creation order.
	order []string

	// alias maps a symlink to the directory it resolves to.
	alias map[string]string

	// explicitDirs lists the directory members, spelled and applied.
	explicitDirs [][2]string

	// budget is how many bytes of file data remain to be written.
	budget int64
}

// randomLayer returns a random layer whose file data totals about budget.
func randomLayer(rng *rand.Rand, budget int64) []byte {
	var buf bytes.Buffer
	g := &layerGenerator{rng: rng, tw: tar.NewWriter(&buf), kinds: map[string]byte{}, alias: map[string]string{}, budget: budget}

	for range 5 + rng.IntN(40) {
		g.writeMember()
	}

	if err := g.tw.Close(); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// paths returns the applied paths of kind in creation order.
func (g *layerGenerator) paths(kind byte) []string {
	var out []string
	for _, p := range g.order {
		if g.kinds[p] == kind {
			out = append(out, p)
		}
	}

	return out
}

// parent returns where a new member goes, as spelled in the archive and as
// applied: the root, a directory, a symlink to one, or a fresh directory
// Apply creates implicitly.
func (g *layerGenerator) parent() (spelled, applied string) {
	dirs := append([]string{""}, g.paths('d')...)
	var links []string
	for _, l := range g.paths('l') {
		if d, ok := g.alias[l]; ok && (d == "" || g.kinds[d] == 'd') {
			links = append(links, l)
		}
	}

	switch k := g.rng.IntN(10); {
	case k < 2 && len(links) > 0:
		l := pick(g.rng, links)
		return l, g.alias[l]
	case k == 2:
		d := path.Join(pick(g.rng, dirs), "implicit"+strconv.Itoa(g.rng.IntN(10)))
		if kind, ok := g.kinds[d]; !ok || kind == 'd' {
			return d, d
		}
	}

	d := pick(g.rng, dirs)
	return d, d
}

// name returns a member name of kind as spelled and as applied: usually
// new, sometimes an existing path the member overrides. It avoids paths
// whose replacement would leave a directory member unresolvable for the
// mtime pass at the end of Apply, which fails the layer.
func (g *layerGenerator) name(kind byte) (spelled, applied string) {
	for range 8 {
		if len(g.order) > 0 && g.rng.IntN(5) == 0 {
			spelled = pick(g.rng, g.order)
			applied = spelled
		} else {
			s, a := g.parent()
			component := pick(g.rng, nameComponents)
			spelled, applied = path.Join(s, component), path.Join(a, component)
		}

		if !g.strandsDirs(applied, kind) {
			return spelled, applied
		}
	}

	s, a := g.parent()
	return path.Join(s, "fresh"), path.Join(a, "fresh")
}

// strandsDirs reports whether applying kind at p would leave a directory
// member's name resolving to nothing.
func (g *layerGenerator) strandsDirs(p string, kind byte) bool {
	old, ok := g.kinds[p]
	if !ok || (old == 'd' && kind == 'd') {
		return false
	}

	for _, dir := range g.explicitDirs {
		for _, name := range dir {
			if strings.HasPrefix(name, p+"/") || (name == p && kind == 'l') {
				return true
			}
		}
	}

	return false
}

// commit records that p was applied as kind: Apply replaces whatever was
// there unless both are directories, and creates missing parents.
func (g *layerGenerator) commit(p string, kind byte) {
	// Drop what the member replaces, along with everything under it.
	if old, ok := g.kinds[p]; ok && (old != 'd' || kind != 'd') {
		g.order = slices.DeleteFunc(g.order, func(q string) bool {
			if q == p || strings.HasPrefix(q, p+"/") {
				delete(g.kinds, q)
				delete(g.alias, q)
				return true
			}

			return false
		})
	}

	// Create the missing parents, then the member itself.
	for d := path.Dir(p); d != "."; d = path.Dir(d) {
		if _, ok := g.kinds[d]; !ok {
			g.kinds[d] = 'd'
			g.order = append(g.order, d)
		}
	}
	if _, ok := g.kinds[p]; !ok {
		g.order = append(g.order, p)
	}
	g.kinds[p] = kind
}

// decorate spells name the ways layer writers do.
func (g *layerGenerator) decorate(name string, dir bool) string {
	switch g.rng.IntN(10) {
	case 0:
		name = "./" + name
	case 1:
		name = "/" + name
	}

	if dir && g.rng.IntN(2) == 0 {
		name += "/"
	}

	return name
}

// writeMember writes one random member and records what Apply makes of it.
func (g *layerGenerator) writeMember() {
	// Pick the fields every member type shares.
	hdr := tar.Header{
		Mode:    int64(pick(g.rng, []int{0o644, 0o755, 0o600, 0o777, 0o4755, 0o2755, 0o1777, 0, g.rng.IntN(0o7777 + 1)})),
		Uid:     pick(g.rng, []int{0, 0, 1000, g.rng.IntN(1 << 16), 1 << 21, 1<<31 + 5}),
		Gid:     pick(g.rng, []int{0, 0, 1000, g.rng.IntN(1 << 16), 1 << 21}),
		ModTime: g.mtime(),
		Format:  pick(g.rng, []tar.Format{tar.FormatUnknown, tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU}),
	}
	if g.rng.IntN(4) == 0 {
		hdr.Uname, hdr.Gname = "user", "group"
	}

	// Pick the member type and the name and body that go with it.
	var body []byte
	var applied string
	kind := byte('f')
	var alias string
	isAlias := false

	switch k := g.rng.IntN(100); {
	case k < 35:
		hdr.Typeflag = tar.TypeReg
		hdr.Name, applied = g.name(kind)
		body = g.body()
		hdr.Size = int64(len(body))
	case k < 50:
		hdr.Typeflag = tar.TypeDir
		kind = 'd'
		hdr.Name, applied = g.name(kind)
	case k < 62:
		hdr.Typeflag = tar.TypeSymlink
		kind = 'l'
		hdr.Name, applied = g.name(kind)
		hdr.Linkname, alias, isAlias = g.symlinkTarget(applied)
	case k < 72:
		hdr.Typeflag = tar.TypeLink
		hdr.Name, applied = g.name(kind)

		// Apply removes what the link replaces before linking.
		targets := slices.DeleteFunc(g.paths('f'), func(p string) bool {
			return p == applied || strings.HasPrefix(p, applied+"/")
		})
		switch {
		case len(targets) > 0 && g.rng.IntN(40) > 0:
			hdr.Linkname = g.decorate(pick(g.rng, targets), false)
		case g.rng.IntN(10) == 0:
			hdr.Linkname = "missing"
		default:
			hdr.Typeflag = tar.TypeReg
		}
	case k < 78:
		hdr.Typeflag = pick(g.rng, []byte{tar.TypeChar, tar.TypeBlock})
		hdr.Name, applied = g.name(kind)
		hdr.Devmajor, hdr.Devminor = int64(g.rng.IntN(300)), int64(g.rng.IntN(1<<20))
	case k < 82:
		hdr.Typeflag = tar.TypeFifo
		hdr.Name, applied = g.name(kind)
	default:
		hdr.Typeflag = tar.TypeReg
		s, a := g.parent()
		component := ".wh..wh..opq"
		if k < 94 {
			component = ".wh." + pick(g.rng, nameComponents)
		}
		hdr.Name, applied = path.Join(s, component), path.Join(a, component)
		if g.strandsDirs(applied, kind) {
			return
		}
	}

	// Give some members extended attributes.
	if g.rng.IntN(4) == 0 {
		hdr.PAXRecords = map[string]string{}
		for range 1 + g.rng.IntN(3) {
			xattr := pick(g.rng, memberXattrs)
			hdr.PAXRecords["SCHILY.xattr."+xattr[0]] = xattr[1]
		}
	}

	// Write the member, letting Go choose the format when the chosen one
	// cannot encode the header.
	spelled := hdr.Name
	hdr.Name = g.decorate(hdr.Name, hdr.Typeflag == tar.TypeDir)
	if err := g.tw.WriteHeader(&hdr); err != nil {
		hdr.Format = tar.FormatUnknown
		if err := g.tw.WriteHeader(&hdr); err != nil {
			return
		}
	}
	if _, err := g.tw.Write(body); err != nil {
		panic(err)
	}

	// Record what Apply makes of the member.
	g.commit(applied, kind)
	if isAlias {
		g.alias[applied] = alias
	}
	if kind == 'd' {
		g.explicitDirs = append(g.explicitDirs, [2]string{spelled, applied})
	}
}

// mtime returns a modification time: the epoch, before it, with
// nanoseconds, past the octal field's reach, or recent.
func (g *layerGenerator) mtime() time.Time {
	switch g.rng.IntN(6) {
	case 0:
		return time.Unix(0, 0)
	case 1:
		return time.Unix(-g.rng.Int64N(1<<31), 0)
	case 2:
		return time.Unix(g.rng.Int64N(1<<31), g.rng.Int64N(1e9))
	case 3:
		return time.Unix(1<<33+g.rng.Int64N(1<<20), 0)
	default:
		return time.Unix(1600000000+g.rng.Int64N(1e8), 0)
	}
}

// body returns file data: random bytes, zeros, or random bytes around
// chunk-aligned zero runs the builder turns into holes.
func (g *layerGenerator) body() []byte {
	size := min(pick(g.rng, fileSizes), max(g.budget, 0))
	g.budget -= size
	b := make([]byte, size)

	switch g.rng.IntN(4) {
	case 0:
	case 1:
		fillRandom(g.rng, b)
		if size > 128<<10 {
			start := int64(g.rng.IntN(int(size/(64<<10)))) * (64 << 10)
			clear(b[start:min(start+64<<10*int64(1+g.rng.IntN(16)), size)])
		}
	default:
		fillRandom(g.rng, b)
	}

	return b
}

// fillRandom fills b with random bytes.
func fillRandom(rng *rand.Rand, b []byte) {
	for i := 0; i < len(b); i += 8 {
		v := rng.Uint64()
		for j := i; j < min(i+8, len(b)); j++ {
			b[j] = byte(v)
			v >>= 8
		}
	}
}

// symlinkTarget returns the target of a symlink applied at p: often a
// directory, absolute or escaping upwards, which later members resolve
// through, else anything, a loop, or dangling.
func (g *layerGenerator) symlinkTarget(p string) (target, dir string, isDir bool) {
	// Point at a directory, absolute or relative with some extra "..".
	if g.rng.IntN(3) == 0 {
		dir = pick(g.rng, append([]string{""}, g.paths('d')...))
		if g.rng.IntN(2) == 0 {
			return "/" + dir, dir, true
		}

		up := 0
		if parent := path.Dir(p); parent != "." {
			up = strings.Count(parent, "/") + 1
		}
		if target = strings.Repeat("../", up+g.rng.IntN(3)) + dir; target == "" {
			target = "."
		}

		return target, dir, true
	}

	// Point at anything else, through a loop, or at nothing.
	other := "missing"
	if len(g.order) > 0 {
		other = pick(g.rng, g.order)
	}

	switch g.rng.IntN(6) {
	case 0:
		return "/" + other, "", false
	case 1:
		return strings.Repeat("../", 1+g.rng.IntN(4)) + other, "", false
	case 2:
		return path.Base(other), "", false
	case 3:
		return other + "/../" + pick(g.rng, nameComponents), "", false
	case 4:
		return path.Base(p), "", false
	default:
		return "missing/" + pick(g.rng, nameComponents), "", false
	}
}

// mutateLayer returns a copy of data with one random corruption and a name
// for it.
func mutateLayer(rng *rand.Rand, data []byte) ([]byte, string) {
	// Truncate when there is no header to corrupt, and sometimes anyway.
	data = bytes.Clone(data)
	headers := headerOffsets(data)
	if len(headers) == 0 || rng.IntN(8) == 0 {
		n := rng.IntN(len(data))
		return data[:n], fmt.Sprintf("truncate-%d", n)
	}

	// Corrupt one header block, or the PAX records that follow one, which
	// are data outside the checksum.
	offset := pick(rng, headers)
	block := data[offset : offset+512]
	switch k := rng.IntN(10); {
	case k == 0 && block[156] == tar.TypeXHeader && parseOctal(block[124:136]) > 0:
		i := offset + 512 + rng.IntN(int(parseOctal(block[124:136])))
		data[i] = pick(rng, []byte{'0', '9', '=', ' ', '\n', 0, 0xff})
		return data, fmt.Sprintf("pax-%d-%#x", i, data[i])
	case k == 1:
		block[148+rng.IntN(8)] ^= 1 << rng.IntN(8)
		return data, fmt.Sprintf("chksum-%d", offset)
	case k < 4:
		block[156] = pick(rng, []byte("0123456789xgLKSDAIMNVX\x00 "))
		fixChecksum(block)
		return data, fmt.Sprintf("typeflag-%d-%q", offset, block[156])
	case k < 6:
		field := pick(rng, ustarFields)
		v := pick(rng, []int64{0, 1, 0o7777777, 0o77777777777, 1 << 20, -1, rng.Int64N(1 << 40)})
		copy(block[field.offset:field.offset+field.length], formatNumeric(rng, v, field.length))
		fixChecksum(block)
		return data, fmt.Sprintf("%s-%d-%d", field.name, offset, v)
	default:
		field := pick(rng, ustarFields)
		i := field.offset + rng.IntN(field.length)
		block[i] = pick(rng, []byte{'0', '7', '8', ' ', 0, 0x80, 0xff, '/', '.', byte(rng.IntN(256))})
		fixChecksum(block)
		return data, fmt.Sprintf("%s-%d-%#x", field.name, i, block[i])
	}
}

// formatNumeric encodes v into an n-byte numeric field in octal, or in GNU
// base-256 for negative values and on a coin flip.
func formatNumeric(rng *rand.Rand, v int64, n int) []byte {
	b := make([]byte, n)
	if v < 0 || rng.IntN(4) == 0 {
		for i := n - 1; i >= 0; i-- {
			b[i] = byte(v)
			v >>= 8
		}
		b[0] |= 0x80

		return b
	}

	s := strconv.FormatInt(v, 8)
	if len(s) >= n {
		s = s[len(s)-n+1:]
	}
	copy(b, fmt.Sprintf("%0*s", n-1, s))

	return b
}

// headerOffsets walks data's header blocks, stopping at the first zero
// block or at data it cannot follow.
func headerOffsets(data []byte) []int {
	var offsets []int
	for off := 0; off+512 <= len(data); {
		block := data[off : off+512]
		if bytes.Count(block, []byte{0}) == 512 {
			break
		}

		offsets = append(offsets, off)
		size := parseOctal(block[124:136])
		if size < 0 {
			break
		}
		off += 512 + int((size+511)&^511)
	}

	return offsets
}

// parseOctal parses a space or NUL padded octal field, returning -1 when it
// is not one or exceeds 1<<40.
func parseOctal(b []byte) int64 {
	s := strings.Trim(string(b), " \x00")
	v, err := strconv.ParseInt(s, 8, 64)
	if err != nil || v > 1<<40 {
		return -1
	}

	return v
}

// fixChecksum recomputes a header block's checksum after an edit.
func fixChecksum(block []byte) {
	copy(block[148:156], "        ")

	var sum int64
	for _, c := range block {
		sum += int64(c)
	}

	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
}
