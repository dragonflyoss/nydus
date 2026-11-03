package tar

import (
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const randomTarSeeds = 200

func TestRandomTars(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	seeds := env.Int(t, "NYDUS_E2E_TAR_SEEDS", randomTarSeeds)
	if !assert.Positive(t, seeds) {
		t.FailNow()
	}

	layouts := slices.Sorted(maps.Keys(tarLayouts))
	var converted, ran atomic.Int32

	t.Cleanup(func() {
		if !t.Failed() {
			assert.GreaterOrEqual(t, converted.Load(), ran.Load()*2/3)
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

			if layout.checkTarConversion(t, randomTar(rng, 8<<20)) == tarConverted {
				converted.Add(1)
			}
		})
	}
}

func TestMutatedTars(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	bases := make([][]byte, 10)
	for i := range bases {
		bases[i] = randomTar(newTarRand(1000+uint64(i)), 64<<10)

		t.Run(fmt.Sprintf("base-%d", i), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tarConverted, (tarLayout{}).checkTarConversion(t, bases[i]))
		})
	}

	for seed := range 150 {
		rng := newTarRand(2000 + uint64(seed))
		data, desc := mutateTar(rng, bases[seed%len(bases)])

		t.Run(fmt.Sprintf("%03d-%s", seed, desc), func(t *testing.T) {
			t.Parallel()
			(tarLayout{}).checkTarConversion(t, data)
		})
	}
}
