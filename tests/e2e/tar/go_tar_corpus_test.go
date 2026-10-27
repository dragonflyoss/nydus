package tar

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

// hugeCorpusArchives declare 60 GB sparse files the reference would
// materialize; manual/hugetar converts them against a streamed judge.
var hugeCorpusArchives = map[string]bool{"gnu-sparse-big.tar": true, "pax-sparse-big.tar": true}

// TestGoTarCorpus converts every archive of Go's archive/tar test corpus
// and checks the mount against the tree containerd applies from the same
// archive; archives Go or containerd rejects must be rejected too.
func TestGoTarCorpus(t *testing.T) {
	t.Parallel()
	// Root also for the reference tree, which restores ownership and device
	// nodes.
	mount.FUSE{}.Require(t)
	testdata := goTarTestdata(t)
	archives, err := filepath.Glob(filepath.Join(testdata, "*.tar*"))
	require.NoError(t, err)
	require.NotEmpty(t, archives, "no archives in %s", testdata)

	for _, path := range archives {
		name := strings.TrimSuffix(filepath.Base(path), obscuredSuffix)
		if hugeCorpusArchives[name] {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireJudged(t, checkTarConversion(t, readCorpusArchive(t, path), tarLayout{}))
		})
	}
}
