package contract

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// C01: the mount reproduces the image's tree exactly: paths, metadata,
// content, link targets, hardlink groups and xattrs.
func init() {
	Register(Case{ID: "C01", Name: "Tree", Scope: Semantic | Data, Run: runTree})
}

func runTree(t *testing.T, f *Fixture) {
	t.Run("Manifest", func(t *testing.T) {
		t.Parallel()
		oracle.VerifyMount(t, f.Root, f.Image.Want, f.Image.Compare())
	})

	// The differential against the source tree on disk adds what the manifest
	// does not record: raw dirents, out-of-order and mmap reads from a cold
	// page cache. It is costly, so only the semantic image gets it.
	if f.Image.Source == "" || f.Image.Merged || f.Image.Corpus != fixture.Stress {
		return
	}
	t.Run("Differential", func(t *testing.T) {
		t.Parallel()
		oracle.DiffTree(t, f.Image.Source, f.Root, oracle.Options{})
	})
}
