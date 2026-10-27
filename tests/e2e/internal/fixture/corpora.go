package fixture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// The named corpora.
const (
	// Standard enumerates the cases a human thinks of; the semantic
	// contract cases address its paths by name.
	Standard = "standard"
	// Stress goes after the shapes that only appear at volume: hundreds of
	// sparse and special files, 255-byte names, directories spanning several
	// EROFS blocks, and files past 4GiB.
	Stress = "stress"
	// Seeded is fully deterministic (content and timestamps): it covers
	// every block, chunk and pcluster boundary, inline tails, holes and
	// metadata forms, and is what the layout matrix and golden images use.
	Seeded = "seeded"
	// Layers holds three layer trees, layer1 (lowest) to layer3, whose
	// overlay exercises every whiteout form.
	Layers = "layers"
	// Huge holds the files past 4GiB; see corpus.MakeHuge.
	Huge = "huge"
)

// StressSeed keeps the stress tree reproducible.
const StressSeed = 20260806

// LayerCount is the number of layer trees in the Layers corpus.
const LayerCount = 3

var generators = map[string]func(t env.TB, dir string){
	Standard: func(t env.TB, dir string) { corpus.MakeStandardCorpus(t, dir) },
	Stress:   func(t env.TB, dir string) { corpus.MakeStressCorpus(t, dir, StressSeed) },
	Seeded:   corpus.MakeSeeded,
	Huge:     corpus.MakeHuge,
	Layers: func(t env.TB, dir string) {
		corpus.MakeMergeLayers(t, layerDirs(dir))
	},
}

func layerDirs(dir string) []string {
	dirs := make([]string, LayerCount)
	for i := range dirs {
		dirs[i] = filepath.Join(dir, fmt.Sprintf("layer%d", i+1))
	}
	return dirs
}

// Corpus returns the cached source tree called name. For Layers it is the
// parent of the layer directories; see LayerDirs.
func Corpus(t env.TB, name string) string {
	t.Helper()
	return filepath.Join(corpusEntry(t, name), "tree")
}

// LayerDirs returns the layer trees of the Layers corpus, lowest first.
func LayerDirs(t env.TB) []string {
	t.Helper()
	return layerDirs(Corpus(t, Layers))
}

// corpusEntry builds the corpus with its recorded tree(s) alongside.
func corpusEntry(t env.TB, name string) string {
	t.Helper()
	gen, ok := generators[name]
	if !ok {
		t.Fatalf("no corpus %q", name)
	}
	// Device nodes and ownership need root.
	env.RequireRoot(t)
	return cached(t, "corpus", name, sourceHash(t)+"\x00"+name, func(dir string) {
		tree := filepath.Join(dir, "tree")
		gen(t, tree)
		if name == Layers {
			for i, layer := range layerDirs(tree) {
				writeTree(t, filepath.Join(dir, fmt.Sprintf("layer%d.json", i+1)), oracle.ScanSource(t, layer))
			}
			return
		}
		writeTree(t, filepath.Join(dir, "tree.json"), oracle.ScanSource(t, tree))
	})
}

var (
	treeMu sync.Mutex
	trees  = map[string][]oracle.Entry{}
)

// Tree returns the recorded tree of the corpus called name. The result is
// shared: do not modify it.
func Tree(t env.TB, name string) []oracle.Entry {
	t.Helper()
	return loadTree(t, filepath.Join(corpusEntry(t, name), "tree.json"))
}

// LayerTrees returns the recorded trees of the Layers corpus, lowest first.
func LayerTrees(t env.TB) [][]oracle.Entry {
	t.Helper()
	dir := corpusEntry(t, Layers)
	out := make([][]oracle.Entry, LayerCount)
	for i := range out {
		out[i] = loadTree(t, filepath.Join(dir, fmt.Sprintf("layer%d.json", i+1)))
	}
	return out
}

func loadTree(t env.TB, path string) []oracle.Entry {
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
	var tree []oracle.Entry
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	trees[path] = tree
	return tree
}

func writeTree(t env.TB, path string, tree []oracle.Entry) {
	t.Helper()
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
