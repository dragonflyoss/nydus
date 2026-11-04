package fault

import (
	"bytes"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// TestBitflip corrupts blob data on its way to the reader. A flipped bit
// fails the chunk group's CRC32C and the read with either setting. A
// corruption crafted to keep the CRC32C passes it: fetched groups are not
// checked against their digests, which only vet groups a restart left in the
// cache, so the forged group is served (KI-2).
func TestBitflip(t *testing.T) {
	t.Parallel()
	img := image{fixture.Get(t, "zstd-4k")}
	forged := image{fixture.Get(t, "none-4k")}.forgeCRC(t)

	for _, a := range adapters {
		for _, verify := range []bool{false, true} {
			name := a.Name() + "/Default"
			if verify {
				name = a.Name() + "/Verify"
			}

			t.Run("Registry/"+name, func(t *testing.T) {
				t.Parallel()
				bitflipRegistry(t, a, img, verify)
			})

			t.Run("CRCPreserving/"+name, func(t *testing.T) {
				t.Parallel()
				bitflipForged(t, a, forged, verify)
			})
		}
	}
}

func bitflipRegistry(t *testing.T, a mount.Adapter, img image, verify bool) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, nil, verify)
	m.prime(t)
	big := img.lookup(t, bigFile)

	reg.Registry.Faults.Set(registry.Fault{FlipBit: mount.Ptr(int64(64))})
	r := big.readOnce(t, m.Root)
	r.expectFailed(t)
	r.expectNotWrong(t)

	if !assert.NotZero(t, reg.Registry.Faults.Hits()) {
		t.FailNow()
	}

	reg.Registry.Faults.Clear()
	big.readOnce(t, m.Root).expectCorrect(t)
}

func bitflipForged(t *testing.T, a mount.Adapter, img image, verify bool) {
	m := img.mount(t, a, mount.Options{Config: func(c *mount.Config) {
		if verify {
			c.Storage.SkipVerifyChecksums = mount.Ptr(false)
		}
	}})

	r := m.read(t, forgedFile)
	t.Logf("%s", r)
	assert.True(t, r.err == nil && r.wrong,
		"want the forged bytes served (KI-2); update the docs if fetches check digests now: %s", r)
}

func (img image) forgeCRC(t *testing.T) image {
	t.Helper()
	cp := fixture.Copy(t, img.Image)
	delta := crcNeutralDelta(t)

	src, err := os.Open(filepath.Join(img.Source, forgedFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = src.Close() }()
	window := make([]byte, 64)
	if _, err := src.ReadAt(window, forgedOffset); !assert.NoError(t, err) {
		t.FailNow()
	}

	at := blobOffset(t, cp.Blob(t), window)
	orig := window[:len(delta)]
	bad := make([]byte, len(delta))

	for i := range delta {
		bad[i] = orig[i] ^ delta[i]
	}

	if !assert.Equal(t, crc32.Checksum(orig, castagnoli), crc32.Checksum(bad, castagnoli)) {
		t.FailNow()
	}

	f, err := os.OpenFile(cp.Blob(t), os.O_WRONLY, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()

	if _, err := f.WriteAt(bad, at); !assert.NoError(t, err) {
		t.FailNow()
	}

	return image{cp}
}

func blobOffset(t *testing.T, blob string, window []byte) int64 {
	t.Helper()
	data, err := os.ReadFile(blob)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, 1, bytes.Count(data, window)) {
		t.FailNow()
	}

	return int64(bytes.Index(data, window))
}

func crcNeutralDelta(t *testing.T) []byte {
	t.Helper()
	const n = 12
	zero := crc32.Checksum(make([]byte, n), castagnoli)
	linear := func(d []byte) uint32 { return crc32.Checksum(d, castagnoli) ^ zero }

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
		if !assert.NotNil(t, pivot[b]) {
			t.FailNow()
		}

		w ^= pivot[b].v
		combo ^= pivot[b].combo
	}

	for i := range 32 {
		if combo&(1<<i) != 0 {
			delta[8+i/8] ^= 1 << (i % 8)
		}
	}

	if !assert.Zero(t, linear(delta)) {
		t.FailNow()
	}

	return delta
}

func TestBlobIntegrity(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	img := fixture.Copy(t, fixture.Get(t, "none-4k"))
	want, err := os.ReadFile(filepath.Join(img.Source, forgedFile))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	fixture.FlipByte(t, img.Blob(t), blobOffset(t, img.Blob(t), want[forgedOffset:forgedOffset+64]))
	want[forgedOffset] ^= 0xff

	for _, skip := range []bool{false, true} {
		name := "Default"
		if skip {
			name = "SkipChecksums"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Config: func(c *mount.Config) {
				if skip {
					c.Storage.SkipVerifyChecksums = mount.Ptr(true)
				}
			}})

			got, err := os.ReadFile(filepath.Join(m.Root, forgedFile))

			if skip {
				assert.NoError(t, err)
				assert.True(t, bytes.Equal(want, got))
			} else {
				assert.ErrorIs(t, err, unix.EIO)
				assert.Positive(t, m.API.Metrics(t).Sum("nydus_cache_write_failure_total", `reason="checksum"`))
			}
		})
	}
}
