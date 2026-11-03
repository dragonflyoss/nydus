package fixture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

// The names of the corpora, as Corpus takes them.
const (
	// Standard is the hand-written tree of every file size, name and
	// metadata case the readers must reproduce.
	Standard = "standard"

	// Stress is Standard plus the shapes that only show up at volume.
	Stress = "stress"

	// Seeded is the tree Get builds a plain layout name from.
	Seeded = "seeded"

	// Layers holds the three layer trees merged images are built from; see
	// LayerDirs.
	Layers = "layers"

	// Huge holds the files past 4GiB, kept apart from the other corpora.
	Huge = "huge"

	layerCount = 3
)

var generators = map[string]func(t testing.TB, dir string){
	Standard: corpus.MakeStandard,
	Stress:   corpus.MakeStress,
	Seeded:   corpus.MakeSeeded,
	Huge:     corpus.MakeHuge,
	Layers: func(t testing.TB, dir string) {
		corpus.MakeMergeLayers(t, layerDirs(dir))
	},
}

func layerDirs(dir string) []string {
	dirs := make([]string, layerCount)
	for i := range dirs {
		dirs[i] = filepath.Join(dir, fmt.Sprintf("layer%d", i+1))
	}

	return dirs
}

// Corpus returns the cached source tree called name. For Layers it is the
// parent of the layer directories; see LayerDirs.
func Corpus(t testing.TB, name string) string {
	t.Helper()
	return filepath.Join(corpusEntry(t, name), "tree")
}

// LayerDirs returns the layer trees of the Layers corpus, lowest first.
func LayerDirs(t testing.TB) []string {
	t.Helper()
	return layerDirs(Corpus(t, Layers))
}

// corpusEntry builds the corpus with its recorded tree(s) alongside.
func corpusEntry(t testing.TB, name string) string {
	t.Helper()
	gen, ok := generators[name]
	if !ok {
		t.Fatalf("no corpus %q", name)
	}
	// Device nodes and ownership need root.
	env.RequireRoot(t)

	return cached(t, "corpus", name, sourceHash(t)+"\x00"+name, func(t testing.TB, dir string) {
		tree := filepath.Join(dir, "tree")
		gen(t, tree)

		if name == Layers {
			for i, layer := range layerDirs(tree) {
				writeTree(t, filepath.Join(dir, fmt.Sprintf("layer%d.json", i+1)), fstest.ScanSource(t, layer))
			}

			return
		}

		writeTree(t, filepath.Join(dir, "tree.json"), fstest.ScanSource(t, tree))
	})
}

var (
	treeMu sync.Mutex
	trees  = map[string][]fstest.Entry{}
)

// tree returns the recorded tree of the corpus called name. The result is
// shared: do not modify it.
func tree(t testing.TB, name string) []fstest.Entry {
	t.Helper()
	return loadTree(t, filepath.Join(corpusEntry(t, name), "tree.json"))
}

// layerTrees returns the recorded trees of the Layers corpus, lowest first.
func layerTrees(t testing.TB) [][]fstest.Entry {
	t.Helper()
	dir := corpusEntry(t, Layers)

	out := make([][]fstest.Entry, layerCount)
	for i := range out {
		out[i] = loadTree(t, filepath.Join(dir, fmt.Sprintf("layer%d.json", i+1)))
	}

	return out
}

func loadTree(t testing.TB, path string) []fstest.Entry {
	t.Helper()
	treeMu.Lock()
	defer treeMu.Unlock()

	if tree, ok := trees[path]; ok {
		return tree
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var tree []fstest.Entry
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	trees[path] = tree

	return tree
}

func writeTree(t testing.TB, path string, tree []fstest.Entry) {
	t.Helper()
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
