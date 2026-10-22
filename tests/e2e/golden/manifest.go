// Package golden checks that the images released versions of nydus built
// still read back exactly. Each version's images live in
// testdata/<version>/ with a manifest of the trees they must reproduce;
// cmd/golden-gen writes them at every release.
package golden

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/goldenpolicy"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

// Schema is the manifest format golden-gen writes. Readers must keep
// accepting every schema a committed version uses.
const Schema = 1

// ManifestName is the manifest file in a version directory.
const ManifestName = goldenpolicy.ManifestName

// The trees images reproduce, by Image.Tree.
const (
	TreeCorpus    = "corpus"
	TreeCorpusTar = "corpus-tar"
	TreeHuge      = "huge"
	TreeHugeTar   = "huge-tar"
	TreeMerged    = "merged"
	TreeMergedTar = "merged-tar"
)

// Manifest describes the golden images of one release. Paths are relative
// to the version directory.
type Manifest struct {
	Schema int `json:"schema"`
	// Version is the release, and the name of the version directory.
	Version string `json:"version"`
	// Builder is the `nydus --version` of the binary that built the images.
	Builder string `json:"builder"`
	// Trees are the expected trees, recorded when the images were built so
	// the reader never regenerates a corpus.
	Trees  map[string][]oracle.Entry `json:"trees"`
	Images []Image                   `json:"images"`
}

// Image is one golden image.
type Image struct {
	// Name is the layout name, huge-<layout> for the files past 4GiB, or
	// merged-<layout>.
	Name string `json:"name"`
	// Layout and Args are the `nydus build` layout and its arguments.
	Layout string   `json:"layout"`
	Args   []string `json:"args"`
	Native bool     `json:"native,omitempty"`
	Tar    bool     `json:"tar,omitempty"`
	Merged bool     `json:"merged,omitempty"`
	// Tree names the expected tree in Manifest.Trees.
	Tree      string `json:"tree"`
	Bootstrap string `json:"bootstrap"`
	BlobDir   string `json:"blob_dir"`
	// Blobs are the full data blobs, one per layer, lowest first.
	Blobs []string `json:"blobs"`
}

// Load reads and validates the manifest of the version directory dir.
func Load(dir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	switch {
	case m.Schema != Schema:
		return nil, fmt.Errorf("%s: manifest schema %d, this reader knows %d", dir, m.Schema, Schema)
	case m.Version != filepath.Base(dir):
		return nil, fmt.Errorf("%s: manifest is of version %q", dir, m.Version)
	case len(m.Images) == 0:
		return nil, fmt.Errorf("%s: no images", dir)
	}
	for _, img := range m.Images {
		if _, ok := m.Trees[img.Tree]; !ok {
			return nil, fmt.Errorf("%s: image %s wants tree %q, which the manifest lacks", dir, img.Name, img.Tree)
		}
		if len(img.Blobs) == 0 || (!img.Merged && len(img.Blobs) != 1) {
			return nil, fmt.Errorf("%s: image %s has %d blobs", dir, img.Name, len(img.Blobs))
		}
	}
	return &m, nil
}

// Write stores m in the version directory dir.
func (m *Manifest) Write(dir string) error {
	data, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestName), append(data, '\n'), 0o644)
}
