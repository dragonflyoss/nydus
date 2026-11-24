package conformance

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

func testTree(t *testing.T, m *mounted) {
	t.Run("Manifest", func(t *testing.T) {
		t.Parallel()
		fstest.VerifyMount(t, m.Root, m.Image.Want, m.Image.Compare())
	})

	// A layer tarball does not carry the whole source directory; Manifest
	// judges such an image against its tar view.
	if m.Image.Source == "" || m.Image.Merged || m.Image.Layout.Tar || m.Image.Corpus != fixture.Stress {
		return
	}

	t.Run("Differential", func(t *testing.T) {
		t.Parallel()
		fstest.DiffTree(t, m.Image.Source, m.Root)
	})
}
