// Command golden-gen builds the golden images of a nydus release: the
// golden corpus in every GA layout, and the golden layers merged in every
// merge layout, with a manifest of the trees they must reproduce. It writes
// <out>/<version>/, which is committed so that every later nydus is tested
// against it (tests/e2e/golden).
//
// It needs root for the corpus' device nodes, owners and trusted xattrs:
//
//	go build -o /tmp/golden-gen ./cmd/golden-gen
//	sudo /tmp/golden-gen -nydus /path/to/released/nydus -out golden/testdata
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/dragonflyoss/nydus/tests/e2e/golden"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

var versionName = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

func main() {
	nydusFlag := flag.String("nydus", "", "the released `nydus` binary that builds the images (required)")
	out := flag.String("out", "", "the golden testdata `dir`, tests/e2e/golden/testdata (required)")
	version := flag.String("version", "", "version directory `name`; defaults to v<version> of `nydus --version`")
	force := flag.Bool("force", false, "replace an existing version directory")
	flag.Parse()
	if *nydusFlag == "" || *out == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := generateVersion(*nydusFlag, *out, *version, *force); err != nil {
		log.Fatal(err)
	}
}

func generateVersion(nydusPath, out, version string, force bool) error {
	nydus, err := filepath.Abs(nydusPath)
	if err != nil {
		return err
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("golden-gen must run as root: the corpus has device nodes, foreign owners and trusted xattrs")
	}
	// fixture builds with env.Nydus, which honours NYDUS_BIN.
	if err := os.Setenv("NYDUS_BIN", nydus); err != nil {
		return err
	}
	if _, err := env.LookupBin("nydus"); err != nil {
		return err
	}

	builder, err := nydusVersion(nydus)
	if err != nil {
		return err
	}
	if version == "" {
		if fields := strings.Fields(builder); len(fields) >= 2 {
			version = "v" + strings.TrimPrefix(fields[1], "v")
		}
	}
	if !versionName.MatchString(version) {
		return fmt.Errorf("version %q (from %q) is not vX.Y.Z[-pre]; pass -version", version, builder)
	}

	final := filepath.Join(out, version)
	if _, err := os.Stat(final); err == nil && !force {
		return fmt.Errorf("%s exists; pass -force to replace it", final)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	// Work next to the output: the same filesystem lets the result be
	// renamed into place, and unlike a tmpfs /tmp on older kernels it takes
	// user xattrs.
	work, err := os.MkdirTemp(out, ".golden-gen-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()

	log.Printf("building the golden images of %s with %s (%s)", version, nydus, builder)
	stage := filepath.Join(work, version)
	t := newTB(work)
	if !t.run(func(t *tb) { generate(t, stage, version, builder) }) {
		return fmt.Errorf("building the golden images of %s failed", version)
	}

	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(stage, final); err != nil {
		return err
	}
	if err := chownToSudoUser(final); err != nil {
		return err
	}
	return report(final)
}

// generate builds every golden image of version into stage and writes the
// manifest.
func generate(t env.TB, stage, version, builder string) {
	buildImages(t, stageSources(t, t.TempDir()), stage, version, builder)
}

// hugeLayouts are the layouts the files past 4GiB are built with: a layout
// indexes every block or chunk of a file, so in the others the index of
// their holes alone takes megabytes.
var hugeLayouts = []string{"zstd", "zstd-8m", "tar-zstd"}

// sources are the trees the golden images are built from.
type sources struct {
	corpus, huge string
	layers       []string
}

func stageSources(t env.TB, work string) sources {
	src := sources{
		corpus: filepath.Join(work, "corpus"),
		huge:   filepath.Join(work, "huge"),
		layers: []string{filepath.Join(work, "layer1"), filepath.Join(work, "layer2"), filepath.Join(work, "layer3")},
	}
	corpus.MakeGolden(t, src.corpus)
	corpus.MakeGoldenHuge(t, src.huge)
	corpus.MakeGoldenLayers(t, src.layers)
	return src
}

func buildImages(t env.TB, src sources, stage, version, builder string) {
	layerTrees := make([][]oracle.Entry, len(src.layers))
	layerTarTrees := make([][]oracle.Entry, len(src.layers))
	for i, dir := range src.layers {
		layerTrees[i] = oracle.ScanSource(t, dir)
		layerTarTrees[i] = oracle.TarView(layerTrees[i])
	}
	tree := oracle.ScanSource(t, src.corpus)
	huge := oracle.ScanSource(t, src.huge)
	m := &golden.Manifest{
		Schema:  golden.Schema,
		Version: version,
		Builder: builder,
		Trees: map[string][]oracle.Entry{
			golden.TreeCorpus:    tree,
			golden.TreeCorpusTar: oracle.TarView(tree),
			golden.TreeHuge:      huge,
			golden.TreeHugeTar:   oracle.TarView(huge),
			golden.TreeMerged:    oracle.Overlay(layerTrees...),
			golden.TreeMergedTar: oracle.Overlay(layerTarTrees...),
		},
	}

	for _, l := range fixture.Layouts {
		m.Images = append(m.Images, build(t, stage, l.Name, l, golden.TreeCorpus, golden.TreeCorpusTar, src.corpus))
	}
	for _, name := range hugeLayouts {
		l := layout(t, name)
		m.Images = append(m.Images, build(t, stage, "huge-"+name, l, golden.TreeHuge, golden.TreeHugeTar, src.huge))
	}
	for _, name := range fixture.MergeLayouts {
		l := layout(t, name)
		m.Images = append(m.Images, build(t, stage, fixture.MergedPrefix+name, l, golden.TreeMerged, golden.TreeMergedTar, src.layers...))
	}

	if err := m.Write(stage); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// build builds the image called name of the source directories with layout
// l into stage/name. Several sources are layers, merged lowest first; their
// own bootstraps only feed the merge, as each blob carries its own.
func build(t env.TB, stage, name string, l fixture.Layout, tree, tarTree string, layers ...string) golden.Image {
	log.Printf("building %s", name)
	dir := filepath.Join(stage, name)
	blobDir := filepath.Join(dir, "blobs")
	img := golden.Image{
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
	fixture.Run(t, env.Nydus(t), args...)
	return img
}

func layout(t env.TB, name string) fixture.Layout {
	l, err := fixture.LayoutByName(name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return l
}

func nydusVersion(nydus string) (string, error) {
	t := newTB(os.TempDir())
	var out string
	if !t.run(func(t *tb) { out = fixture.Run(t, nydus, "--version") }) {
		return "", fmt.Errorf("%s --version failed", nydus)
	}
	return strings.TrimSpace(out), nil
}

// chownToSudoUser hands dir to the user who ran golden-gen through sudo, so
// they can commit and remove it.
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

// report logs the size of every image and of the version, which is
// committed to git.
func report(dir string) error {
	sizes := map[string]int64{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sizes[strings.SplitN(rel, string(filepath.Separator), 2)[0]] += info.Size()
		return nil
	})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(sizes))
	var total int64
	for name, size := range sizes {
		names = append(names, name)
		total += size
	}
	sort.Strings(names)
	for _, name := range names {
		log.Printf("%-28s %9d bytes", name, sizes[name])
	}
	log.Printf("%s: %d bytes in total", dir, total)
	return nil
}
