package fault

import (
	"bytes"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

const (
	// forgedFile is 2MiB+1 random bytes, so any 64 of them are unique in
	// the blob.
	forgedFile = "data/size/02097153"
	// forgedOffset is where in forgedFile the forged corruption lands.
	forgedOffset = 1<<20 + 100
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// TestBitflip corrupts blob data on its way to the reader.
//
// A flipped bit in a registry response is always caught: every fetched
// chunk group is checked against its CRC32C by default, so with either setting the read
// fails, and reads back right once the corruption stops.
//
// CRC32C is no integrity check, though. A corruption crafted to keep the
// group's CRC32C passes it. Group digests are no longer verified on the read
// path, so the forged group is served with either setting (KI-2).
func TestBitflip(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	forged := forgeCRC(t, fixture.Get(t, "none-4k"))
	for _, a := range adapters {
		for _, verify := range []bool{false, true} {
			name := a.Name() + "/default"
			if verify {
				name = a.Name() + "/verify"
			}
			t.Run("registry/"+name, func(t *testing.T) {
				t.Parallel()
				bitflipRegistry(t, a, img, verify)
			})
			t.Run("crc-preserving/"+name, func(t *testing.T) {
				t.Parallel()
				bitflipForged(t, a, forged, verify)
			})
		}
	}
}

func bitflipRegistry(t *testing.T, a mount.Adapter, img fixture.Image, verify bool) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, nil, verify)
	prime(t, m)
	big := lookup(t, img, bigFile)

	// Every response from here on is corrupted, retries and refetches too.
	reg.Faults.Set(registry.Fault{FlipBit: mount.Ptr(int64(64))})
	r := readOnce(t, m.Root, big)
	expectFailed(t, r)
	expectNotWrong(t, r)
	if reg.Faults.Hits() == 0 {
		t.Fatalf("no blob request met the fault: the read never reached the registry")
	}

	reg.Faults.Clear()
	expectCorrect(t, readOnce(t, m.Root, big))
}

func bitflipForged(t *testing.T, a mount.Adapter, img fixture.Image, verify bool) {
	m := mount.Mount(t, a, img, mount.Options{Config: func(c *mount.Config) {
		if verify {
			c.Storage.SkipVerifyChecksums = mount.Ptr(false)
		}
	}})
	r := readOnce(t, m.Root, lookup(t, img, forgedFile))
	t.Logf("%s", r)
	expectNotWrong(t, r)
}

// forgeCRC returns a copy of img whose blob has forgedFile corrupted at
// forgedOffset such that the chunk group CRC32C still matches. img must
// store file data verbatim, as an uncompressed layout does.
func forgeCRC(t *testing.T, img fixture.Image) fixture.Image {
	t.Helper()
	cp := fixture.Copy(t, img)
	delta := crcNeutralDelta(t)

	src, err := os.Open(filepath.Join(img.Source, forgedFile))
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer func() { _ = src.Close() }()
	window := make([]byte, 64)
	if _, err := src.ReadAt(window, forgedOffset); err != nil {
		t.Fatalf("read source: %v", err)
	}

	blob, err := os.ReadFile(cp.Blob())
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	at := bytes.Index(blob, window)
	if at < 0 {
		t.Fatalf("%s no longer stores %s verbatim", img.Name, forgedFile)
	}
	if bytes.Contains(blob[at+1:], window) {
		t.Fatalf("the bytes of %s at %d occur twice in the blob", forgedFile, forgedOffset)
	}

	orig := window[:len(delta)]
	bad := make([]byte, len(delta))
	for i := range delta {
		bad[i] = orig[i] ^ delta[i]
	}
	if crc32.Checksum(bad, castagnoli) != crc32.Checksum(orig, castagnoli) {
		t.Fatalf("the forged delta changes the CRC32C")
	}
	f, err := os.OpenFile(cp.Blob(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open blob: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(bad, int64(at)); err != nil {
		t.Fatalf("forge blob: %v", err)
	}
	return cp
}

// crcNeutralDelta returns a 12-byte delta that flips the low bit of its
// first byte and adjusts bytes 8-11 so that XORing it into any message
// leaves the message's CRC32C unchanged. CRC is affine over GF(2), so the
// delta is neutral wherever it lands once its own linear image is zero, and
// any 32 consecutive bits span that image, which makes the system solvable.
func crcNeutralDelta(t *testing.T) []byte {
	t.Helper()
	const n = 12
	zero := crc32.Checksum(make([]byte, n), castagnoli)
	linear := func(d []byte) uint32 { return crc32.Checksum(d, castagnoli) ^ zero }

	// Gaussian elimination: pivot[b] has b as its highest set bit and
	// records which of the 32 free bits sum to it.
	type row struct{ v, combo uint32 }
	var pivot [32]*row
	for i := range 32 {
		d := make([]byte, n)
		d[8+i/8] = 1 << (i % 8)
		r := &row{v: linear(d), combo: 1 << i}
		for b := 31; b >= 0 && r.v != 0; b-- {
			if r.v&(1<<b) == 0 {
				continue
			}
			if pivot[b] == nil {
				pivot[b] = r
				break
			}
			r.v ^= pivot[b].v
			r.combo ^= pivot[b].combo
		}
	}

	delta := make([]byte, n)
	delta[0] = 1
	w, combo := linear(delta), uint32(0)
	for b := 31; b >= 0; b-- {
		if w&(1<<b) == 0 {
			continue
		}
		if pivot[b] == nil {
			t.Fatalf("bytes 8-11 do not span the CRC32C")
		}
		w ^= pivot[b].v
		combo ^= pivot[b].combo
	}
	for i := range 32 {
		if combo&(1<<i) != 0 {
			delta[8+i/8] ^= 1 << (i % 8)
		}
	}
	if linear(delta) != 0 {
		t.Fatalf("no CRC32C-neutral delta found")
	}
	return delta
}
