//go:build manual

// Package hugetar converts the Go tar corpus archives too large for the PR
// suite in tar/.
package hugetar

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

// TestHugeSparseCorpus converts the Go corpus archives whose sparse files
// declare 60 GB, which the builder must turn back into holes, and compares
// the mount with Go's own reading of each archive. It streams 120 GB of
// zeros through the judge, so it is built only with the manual tag:
// go test -tags manual ./manual/hugetar
func TestHugeSparseCorpus(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	testdata := goTarTestdata(t)

	for _, name := range []string{"gnu-sparse-big.tar", "pax-sparse-big.tar"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data := readCorpusArchive(t, corpusArchive(testdata, name))
			work := t.TempDir()
			blob := filepath.Join(work, "layer.blob")
			require.NoError(t, packLayer(t, bytes.NewReader(data), blob))
			img := fixture.Image{Name: "tar-layer", BlobDir: work, Blobs: []string{blob}}
			mnt := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mount.Blob})
			compareStreamed(t, data, mnt.Root)
		})
	}
}
