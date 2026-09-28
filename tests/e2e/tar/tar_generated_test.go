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

	"github.com/dragonflyoss/nydus/tests/e2e"
	"github.com/stretchr/testify/require"
)

// randomTarSeeds is how many archives TestRandomTars generates unless
// NYDUS_E2E_TAR_SEEDS says otherwise.
const randomTarSeeds = 200

// TestRandomTars converts seeded random layers, member mixes no hand-written
// vector covers: overrides of every type by every type, links through
// symlinked parents, hardlinks through any of their names, whiteouts,
// setgid directories, xattrs, and file sizes around the chunk and block
// boundaries, in random header formats and blob layouts. A failing seed
// replays with -run 'TestRandomTars/^seed-05$'.
func TestRandomTars(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: the reference tree restores ownership and device nodes")
	}
	t.Parallel()
	nydusBin := e2e.MustLookupExecutable(t, "nydus")
	seeds := randomTarSeeds
	if s := os.Getenv("NYDUS_E2E_TAR_SEEDS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			t.Fatalf("NYDUS_E2E_TAR_SEEDS=%q: want a positive count", s)
		}
		seeds = n
	}
	layouts := slices.Sorted(maps.Keys(tarLayouts))
	var converted, ran atomic.Int32
	// Parallel seeds run after this function returns; a cleanup runs once
	// they all have.
	t.Cleanup(func() {
		// Rejections test little; keep the generator producing valid layers.
		if !t.Failed() && converted.Load() < ran.Load()*2/3 {
			t.Errorf("only %d of %d random layers were valid", converted.Load(), ran.Load())
		}
	})
	for seed := range seeds {
		t.Run(fmt.Sprintf("seed-%02d", seed), func(t *testing.T) {
			t.Parallel()
			ran.Add(1)
			rng := newTarRand(uint64(seed))
			layout := tarLayout{}
			if i := rng.IntN(len(layouts) + 2); i < len(layouts) {
				layout = tarLayouts[layouts[i]]
				t.Logf("layout %s", layouts[i])
			}
			if checkTarConversion(t, nydusBin, randomTar(rng, 8<<20), layout) {
				converted.Add(1)
			}
		})
	}
}

// TestMutatedTars converts random layers with one header field corrupted
// and its checksum recomputed, or cut short, so the reader's validation
// paths meet the builder's: every mutant must convert to exactly what
// containerd applies, or be rejected without a crash.
func TestMutatedTars(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: the reference tree restores ownership and device nodes")
	}
	t.Parallel()
	nydusBin := e2e.MustLookupExecutable(t, "nydus")
	bases := make([][]byte, 10)
	for i := range bases {
		bases[i] = randomTar(newTarRand(1000+uint64(i)), 64<<10)
		t.Run(fmt.Sprintf("base-%d", i), func(t *testing.T) {
			t.Parallel()
			// Mutants of a layer containerd rejects anyway test little.
			require.True(t, checkTarConversion(t, nydusBin, bases[i], tarLayout{}), "base layer rejected")
		})
	}
	for seed := range 150 {
		rng := newTarRand(2000 + uint64(seed))
		data, desc := mutateTar(rng, bases[seed%len(bases)])
		t.Run(fmt.Sprintf("%03d-%s", seed, desc), func(t *testing.T) {
			t.Parallel()
			checkTarConversion(t, nydusBin, data, tarLayout{})
		})
	}
}

// FuzzTarConversion runs checkTarConversion on arbitrary bytes. Without
// -fuzz it replays the seeds; with it, run as root:
// go test -run '^$' -fuzz FuzzTarConversion ./tar
func FuzzTarConversion(f *testing.F) {
	for i := range 4 {
		data := randomTar(newTarRand(3000+uint64(i)), 16<<10)
		f.Add(data)
		f.Add(data[:len(data)/2])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if os.Getuid() != 0 {
			t.Skip("requires root: the reference tree restores ownership and device nodes")
		}
		checkTarConversion(t, e2e.MustLookupExecutable(t, "nydus"), data, tarLayout{})
	})
}

func newTarRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, 0x6e79647573))
}

// tarGen accumulates a random layer, tracking the tree containerd applies
// from it so that most members are valid: each lands in a directory, maybe
// through a symlink to one, and each hardlink names a file.
type tarGen struct {
	rng      *rand.Rand
	tw       *tar.Writer
	kinds    map[string]byte   // applied path: 'd', 'f', or 'l' for a symlink
	order    []string          // the keys of kinds in creation order
	alias    map[string]string // symlink: the directory it resolves to
	explicit [][2]string       // directory members, spelled and applied
	budget   int64
}

// randomTar returns a random layer whose file data totals about budget.
func randomTar(rng *rand.Rand, budget int64) []byte {
	var buf bytes.Buffer
	g := &tarGen{rng: rng, tw: tar.NewWriter(&buf), kinds: map[string]byte{}, alias: map[string]string{}, budget: budget}
	for range 5 + rng.IntN(40) {
		g.member()
	}
	if err := g.tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func pick[T any](rng *rand.Rand, s []T) T {
	return s[rng.IntN(len(s))]
}

var tarComponents = []string{
	"a", "b", "c", "dir", "file", "link", "x y", "ünïcödé", "..dots", "-dash",
	strings.Repeat("n", 120), "nl\nname", "bad\xffutf8", "tab\tname",
}

// paths returns the applied paths of kind in creation order.
func (g *tarGen) paths(kind byte) []string {
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
func (g *tarGen) parent() (spelled, applied string) {
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
func (g *tarGen) name(kind byte) (spelled, applied string) {
	for range 8 {
		if len(g.order) > 0 && g.rng.IntN(5) == 0 {
			spelled = pick(g.rng, g.order)
			applied = spelled
		} else {
			s, a := g.parent()
			c := pick(g.rng, tarComponents)
			spelled, applied = path.Join(s, c), path.Join(a, c)
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
func (g *tarGen) strandsDirs(p string, kind byte) bool {
	old, ok := g.kinds[p]
	if !ok || (old == 'd' && kind == 'd') {
		return false
	}
	for _, dir := range g.explicit {
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
func (g *tarGen) commit(p string, kind byte) {
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
func (g *tarGen) decorate(name string, dir bool) string {
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

var tarXattrs = [][2]string{
	{"user.a", "1"},
	{"user.bin", "\x00\x01\xff"},
	{"user.nl", "a\nb"},
	{"user.empty", ""},
	{"user.long", strings.Repeat("v", 3000)},
	{"trusted.t", "x"},
	{"security.selinux", "system_u:object_r:foo_t:s0\x00"},
}

var tarFileSizes = []int64{
	0, 1, 100, 511, 512, 513, 4095, 4096, 4097, 64<<10 - 1, 64 << 10, 64<<10 + 1,
	1<<20 - 1, 1 << 20, 1<<20 + 1, 2<<20 + 3,
}

func (g *tarGen) member() {
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
		c := ".wh..wh..opq"
		if k < 94 {
			c = ".wh." + pick(g.rng, tarComponents)
		}
		hdr.Name, applied = path.Join(s, c), path.Join(a, c)
		if g.strandsDirs(applied, kind) {
			return
		}
	}
	if g.rng.IntN(4) == 0 {
		hdr.PAXRecords = map[string]string{}
		for range 1 + g.rng.IntN(3) {
			x := pick(g.rng, tarXattrs)
			hdr.PAXRecords["SCHILY.xattr."+x[0]] = x[1]
		}
	}
	spelled := hdr.Name
	hdr.Name = g.decorate(hdr.Name, hdr.Typeflag == tar.TypeDir)
	if err := g.tw.WriteHeader(&hdr); err != nil {
		// The chosen format cannot encode the header; let Go choose.
		hdr.Format = tar.FormatUnknown
		if err := g.tw.WriteHeader(&hdr); err != nil {
			return
		}
	}
	if _, err := g.tw.Write(body); err != nil {
		panic(err)
	}
	g.commit(applied, kind)
	if isAlias {
		g.alias[applied] = alias
	}
	if kind == 'd' {
		g.explicit = append(g.explicit, [2]string{spelled, applied})
	}
}

func (g *tarGen) mtime() time.Time {
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
func (g *tarGen) body() []byte {
	size := min(pick(g.rng, tarFileSizes), max(g.budget, 0))
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
func (g *tarGen) symlinkTarget(p string) (target, dir string, isDir bool) {
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
		return other + "/../" + pick(g.rng, tarComponents), "", false
	case 4:
		return path.Base(p), "", false
	default:
		return "missing/" + pick(g.rng, tarComponents), "", false
	}
}

// ustarFields are the header fields mutateTar corrupts, as offset and
// length within the block.
var ustarFields = []struct {
	name     string
	off, len int
}{
	{"name", 0, 100}, {"mode", 100, 8}, {"uid", 108, 8}, {"gid", 116, 8},
	{"size", 124, 12}, {"mtime", 136, 12}, {"typeflag", 156, 1},
	{"linkname", 157, 100}, {"magic", 257, 6}, {"version", 263, 2},
	{"uname", 265, 32}, {"gname", 297, 32}, {"devmajor", 329, 8},
	{"devminor", 337, 8}, {"prefix", 345, 155},
}

// mutateTar returns a copy of data with one random corruption and a name
// for it.
func mutateTar(rng *rand.Rand, data []byte) ([]byte, string) {
	data = bytes.Clone(data)
	headers := tarHeaderOffsets(data)
	if len(headers) == 0 || rng.IntN(8) == 0 {
		n := rng.IntN(len(data))
		return data[:n], fmt.Sprintf("truncate-%d", n)
	}
	h := pick(rng, headers)
	blk := data[h : h+512]
	switch k := rng.IntN(10); {
	case k == 0 && blk[156] == tar.TypeXHeader && parseOctal(blk[124:136]) > 0:
		// PAX records are data, outside the checksum.
		i := h + 512 + rng.IntN(int(parseOctal(blk[124:136])))
		data[i] = pick(rng, []byte{'0', '9', '=', ' ', '\n', 0, 0xff})
		return data, fmt.Sprintf("pax-%d-%#x", i, data[i])
	case k == 1:
		blk[148+rng.IntN(8)] ^= 1 << rng.IntN(8)
		return data, fmt.Sprintf("chksum-%d", h)
	case k < 4:
		blk[156] = pick(rng, []byte("0123456789xgLKSDAIMNVX\x00 "))
		fixChecksum(blk)
		return data, fmt.Sprintf("typeflag-%d-%q", h, blk[156])
	case k < 6:
		f := pick(rng, ustarFields)
		v := pick(rng, []int64{0, 1, 0o7777777, 0o77777777777, 1 << 20, -1, rng.Int64N(1 << 40)})
		copy(blk[f.off:f.off+f.len], formatField(rng, v, f.len))
		fixChecksum(blk)
		return data, fmt.Sprintf("%s-%d-%d", f.name, h, v)
	default:
		f := pick(rng, ustarFields)
		i := f.off + rng.IntN(f.len)
		blk[i] = pick(rng, []byte{'0', '7', '8', ' ', 0, 0x80, 0xff, '/', '.', byte(rng.IntN(256))})
		fixChecksum(blk)
		return data, fmt.Sprintf("%s-%d-%#x", f.name, i, blk[i])
	}
}

// formatField encodes v into an n-byte numeric field in octal, or in GNU
// base-256 for negative values and on a coin flip.
func formatField(rng *rand.Rand, v int64, n int) []byte {
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

// tarHeaderOffsets walks data's header blocks, stopping at the first zero
// block or at data it cannot follow.
func tarHeaderOffsets(data []byte) []int {
	var offsets []int
	for off := 0; off+512 <= len(data); {
		blk := data[off : off+512]
		if bytes.Count(blk, []byte{0}) == 512 {
			break
		}
		offsets = append(offsets, off)
		size := parseOctal(blk[124:136])
		if size < 0 {
			break
		}
		off += 512 + int((size+511)&^511)
	}
	return offsets
}

func parseOctal(b []byte) int64 {
	s := strings.Trim(string(b), " \x00")
	v, err := strconv.ParseInt(s, 8, 64)
	if err != nil || v > 1<<40 {
		return -1
	}
	return v
}

// fixChecksum recomputes a header block's checksum after an edit.
func fixChecksum(blk []byte) {
	copy(blk[148:156], "        ")
	var sum int64
	for _, c := range blk {
		sum += int64(c)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
}
