package contract

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

func runTree(t *testing.T, f *Fixture) {
	t.Run("Manifest", func(t *testing.T) {
		t.Parallel()
		fstest.VerifyMount(t, f.Root, f.Image.Want, f.Image.Compare())
	})

	// The differential against the source tree on disk adds what the manifest
	// does not record: raw dirents, out-of-order and mmap reads from a cold
	// page cache. It is costly, so only the semantic image gets it.
	if f.Image.Source == "" || f.Image.Merged || f.Image.Corpus != fixture.Stress {
		return
	}

	t.Run("Differential", func(t *testing.T) {
		t.Parallel()
		fstest.DiffTree(t, f.Image.Source, f.Root)
	})
}
