package export

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// TestExport exports the blob of every GA layout image of the seeded corpus,
// and of the files past 4GiB, and compares each OCI layer with its corpus:
// everything a tar can carry.
func TestExport(t *testing.T) {
	t.Parallel()
	nydus := env.Nydus(t)
	names := []string{fixture.HugePrefix + "zstd"}
	for _, layout := range fixture.Layouts {
		names = append(names, layout.Name)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, name)
			oracle.VerifyExport(t, nydus, img.Blob(), img.Want)
		})
	}
}
