package compatibility

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

const (
	schema       = 1
	manifestName = "manifest.json"

	treeCorpus    = "corpus"
	treeCorpusTar = "corpus-tar"
	treeHuge      = "huge"
	treeHugeTar   = "huge-tar"
	treeMerged    = "merged"
	treeMergedTar = "merged-tar"
)

type manifest struct {
	Schema  int                       `json:"schema"`
	Version string                    `json:"version"`
	Builder string                    `json:"builder"`
	Trees   map[string][]fstest.Entry `json:"trees"`
	Images  []image                   `json:"images"`
}

type image struct {
	Name      string   `json:"name"`
	Layout    string   `json:"layout"`
	Args      []string `json:"args"`
	Native    bool     `json:"native,omitempty"`
	Tar       bool     `json:"tar,omitempty"`
	Merged    bool     `json:"merged,omitempty"`
	Tree      string   `json:"tree"`
	Bootstrap string   `json:"bootstrap"`
	BlobDir   string   `json:"blob_dir"`
	Blobs     []string `json:"blobs"`
}

func imageRoot() (string, bool) {
	if root := os.Getenv("NYDUS_E2E_COMPATIBILITY_DIR"); root != "" {
		return root, true
	}

	return "testdata", false
}

func loadManifest(dir string) (*manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, err
	}

	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}

	switch {
	case m.Schema != schema:
		return nil, fmt.Errorf("%s: manifest schema %d, this reader knows %d", dir, m.Schema, schema)

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

func (m *manifest) write(dir string) error {
	data, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, manifestName), append(data, '\n'), 0o644)
}

func (m *manifest) toFixture(dir string, img image) fixture.Image {
	var blobs []string

	for _, b := range img.Blobs {
		blobs = append(blobs, filepath.Join(dir, b))
	}

	return fixture.Image{
		Name:      img.Name,
		Layout:    fixture.Layout{Name: img.Layout, Args: img.Args, Native: img.Native, Tar: img.Tar},
		Corpus:    m.Version + "/" + img.Tree,
		Bootstrap: filepath.Join(dir, img.Bootstrap),
		BlobDir:   filepath.Join(dir, img.BlobDir),
		Blobs:     blobs,
		Merged:    img.Merged,
		Want:      m.Trees[img.Tree],
	}
}
