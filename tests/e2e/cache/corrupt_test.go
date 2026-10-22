package cache

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// TestCorrupt damages a shared cache while no daemon runs and checks that a
// fresh daemon never returns wrong bytes from it: it must notice and refetch,
// or fail the read. Cache hits are read straight from the data file and are
// not verified even with checksum verification on, so every case currently
// reproduces KI-2.
func TestCorrupt(t *testing.T) {
	t.Parallel()
	w := setup(t)
	damages := []struct {
		name   string
		damage func(t *testing.T, cacheDir string)
	}{
		// Bit rot in groups that are correctly marked ready.
		{"data-bytes", func(t *testing.T, cacheDir string) {
			warm := mountOn(t, w.image1, cacheDir)
			mustRead(t, warm.Path("shared.bin"), w.want["shared.bin"])
			warm.Unmount()
			if n := flipData(t, cacheFile(cacheDir, w.keyB, dataSuffix)); n == 0 {
				t.Fatalf("warm cache holds no data to corrupt")
			}
		}},
		// Ready bits for groups that were never written, as a torn map
		// write or a lost data file page would leave.
		{"map-bits", func(t *testing.T, cacheDir string) {
			warm := mountOn(t, w.image1, cacheDir, fetchSize(64<<10))
			mustReadAt(t, warm.Path("shared.bin"), 0, 4096, w.data["shared.bin"])
			warm.Unmount()
			if n := forgeReady(t, cacheFile(cacheDir, w.keyB, mapSuffix)); n == 0 {
				t.Fatalf("partial fill left no unready group to forge")
			}
		}},
	}
	for _, d := range damages {
		for _, verify := range []bool{false, true} {
			name := d.name + "-default"
			var edits []func(*mount.Config)
			if verify {
				name = d.name + "-verify"
				edits = append(edits, verifyChecksums)
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				cacheDir := newCache(t)
				d.damage(t, cacheDir)
				fresh := mountOn(t, w.image1, cacheDir, edits...)
				env.KnownIssue(t, "KI-2", func(t env.TB) {
					checkRead(t, fresh.Path("shared.bin"), w.want["shared.bin"])
				})
			})
		}
	}
}
