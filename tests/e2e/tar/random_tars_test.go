package tar

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// randomTarSeeds is how many layers TestRandomTars generates unless
// NYDUS_E2E_TAR_SEEDS asks for more (or fewer) in a longer run.
const randomTarSeeds = 200

// TestRandomTars converts seeded random layers, member mixes no hand-written
// vector covers: overrides of every type by every type, links through
// symlinked parents, hardlinks through any of their names, whiteouts,
// setgid directories, xattrs, and file sizes around the chunk and block
// boundaries, in random header formats and blob layouts. A failing seed
// replays with -run 'TestRandomTars/^seed-05$'.
func TestRandomTars(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
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
			t.Errorf("only %d of %d random layers were converted", converted.Load(), ran.Load())
		}
	})
	for seed := range seeds {
		t.Run(fmt.Sprintf("seed-%02d", seed), func(t *testing.T) {
			t.Parallel()
			ran.Add(1)
			rng := newTarRand(uint64(seed))
			layout := tarLayout{}
			// The default layout gets two shares, the others one each.
			if i := rng.IntN(len(layouts) + 2); i < len(layouts) {
				layout = tarLayouts[layouts[i]]
				t.Logf("layout %s", layouts[i])
			}
			if checkTarConversion(t, randomTar(rng, 8<<20), layout) == tarConverted {
				converted.Add(1)
			}
		})
	}
}
