package tar

import (
	"fmt"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

// TestMutatedTars converts random layers with one header field corrupted
// and its checksum recomputed, or cut short, so the reader's validation
// paths meet the builder's: every mutant must convert to exactly what
// containerd applies, or be rejected without a crash.
func TestMutatedTars(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	bases := make([][]byte, 10)
	for i := range bases {
		bases[i] = randomTar(newTarRand(1000+uint64(i)), 64<<10)
		t.Run(fmt.Sprintf("base-%d", i), func(t *testing.T) {
			t.Parallel()
			// Mutants of a layer containerd rejects anyway test little.
			require.Equal(t, tarConverted, checkTarConversion(t, bases[i], tarLayout{}), "base layer not converted")
		})
	}
	for seed := range 150 {
		rng := newTarRand(2000 + uint64(seed))
		data, desc := mutateTar(rng, bases[seed%len(bases)])
		t.Run(fmt.Sprintf("%03d-%s", seed, desc), func(t *testing.T) {
			t.Parallel()
			checkTarConversion(t, data, tarLayout{})
		})
	}
}
