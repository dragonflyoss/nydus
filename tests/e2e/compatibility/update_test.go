package compatibility

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
)

var update = flag.Bool("update", false, "build the compatibility images of NYDUS_BIN into the image directory instead of reading them")

var hugeLayouts = []string{"zstd", "zstd-8m", "tar-zstd"}

var versionName = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

func updateImages(t *testing.T) {
	t.Helper()
	env.RequireRoot(t)
	nydus := env.Nydus(t)
	builder := nydusVersion(t, nydus)

	version := ""
	if fields := strings.Fields(builder); len(fields) >= 2 {
		version = "v" + strings.TrimPrefix(fields[1], "v")
	}

	if !assert.Regexp(t, versionName, version) {
		t.FailNow()
	}

	root, _ := imageRoot()
	out, err := filepath.Abs(root)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NoError(t, os.MkdirAll(out, 0o755)) {
		t.FailNow()
	}

	work, err := os.MkdirTemp(out, ".update-")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = os.RemoveAll(work) })
	t.Logf("building the compatibility images of %s with %s (%s)", version, nydus, builder)

	stage := filepath.Join(work, version)
	stageSources(t, filepath.Join(work, "src")).buildImages(t, stage, version, builder)
	final := filepath.Join(out, version)
	if !assert.NoError(t, os.RemoveAll(final)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.Rename(stage, final)) {
		t.FailNow()
	}

	assert.NoError(t, chownToSudoUser(final))
	t.Logf("wrote %s", final)
}

type sources struct {
	corpus, huge string
	layers       []string
}

func stageSources(t *testing.T, work string) sources {
	t.Helper()
	src := sources{
		corpus: filepath.Join(work, "corpus"),
		huge:   filepath.Join(work, "huge"),
		layers: []string{filepath.Join(work, "lower"), filepath.Join(work, "middle"), filepath.Join(work, "upper")},
	}

	corpus.MakeCompatibility(t, src.corpus)
	corpus.MakeCompatibilityHuge(t, src.huge)
	corpus.MakeCompatibilityLayers(t, src.layers)

	return src
}

func (src sources) buildImages(t *testing.T, stage, version, builder string) {
	t.Helper()
	layerTrees := make([][]fstest.Entry, len(src.layers))
	layerTarTrees := make([][]fstest.Entry, len(src.layers))

	for i, dir := range src.layers {
		layerTrees[i] = fstest.ScanSource(t, dir)
		layerTarTrees[i] = fstest.TarView(layerTrees[i])
	}

	tree := fstest.ScanSource(t, src.corpus)
	huge := fstest.ScanSource(t, src.huge)

	m := &manifest{
		Schema:  schema,
		Version: version,
		Builder: builder,
		Trees: map[string][]fstest.Entry{
			treeCorpus:    tree,
			treeCorpusTar: fstest.TarView(tree),
			treeHuge:      huge,
			treeHugeTar:   fstest.TarView(huge),
			treeMerged:    fstest.Overlay(layerTrees...),
			treeMergedTar: fstest.Overlay(layerTarTrees...),
		},
	}

	for _, l := range fixture.Layouts {
		m.Images = append(m.Images, buildImage(t, stage, l.Name, l, treeCorpus, treeCorpusTar, src.corpus))
	}

	for _, name := range hugeLayouts {
		m.Images = append(m.Images, buildImage(t, stage, fixture.HugePrefix+name, fixture.MustLayout(t, name), treeHuge, treeHugeTar, src.huge))
	}

	for _, name := range fixture.MergeLayouts {
		m.Images = append(m.Images, buildImage(t, stage, fixture.MergedPrefix+name, fixture.MustLayout(t, name), treeMerged, treeMergedTar, src.layers...))
	}

	if !assert.NoError(t, m.write(stage)) {
		t.FailNow()
	}
}

func buildImage(t *testing.T, stage, name string, l fixture.Layout, tree, tarTree string, layers ...string) image {
	t.Helper()
	t.Logf("building %s", name)
	dir := filepath.Join(stage, name)
	blobDir := filepath.Join(dir, "blobs")

	img := image{
		Name:      name,
		Layout:    l.Name,
		Args:      l.Args,
		Native:    l.Native,
		Tar:       l.Tar,
		Merged:    len(layers) > 1,
		Tree:      tree,
		Bootstrap: filepath.Join(name, "image.bootstrap"),
		BlobDir:   filepath.Join(name, "blobs"),
	}

	if l.Tar {
		img.Tree = tarTree
	}

	bootstrap := filepath.Join(dir, "image.bootstrap")

	if !img.Merged {
		blob, _ := fixture.BuildInto(t, blobDir, bootstrap, layers[0], l)
		img.Blobs = []string{filepath.Join(name, "blobs", filepath.Base(blob))}
		return img
	}

	scratch := t.TempDir()
	args := []string{"merge", "--bootstrap", bootstrap}

	for i, layer := range layers {
		blob, _ := fixture.BuildInto(t, blobDir, filepath.Join(scratch, fmt.Sprintf("layer%d.bootstrap", i+1)), layer, l)
		args = append(args, blob)
		img.Blobs = append(img.Blobs, filepath.Join(name, "blobs", filepath.Base(blob)))
	}

	env.Run(t, env.Nydus(t), args...)

	return img
}

func chownToSudoUser(dir string) error {
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uidErr != nil || gidErr != nil {
		return nil
	}

	return filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		return os.Lchown(path, uid, gid)
	})
}
