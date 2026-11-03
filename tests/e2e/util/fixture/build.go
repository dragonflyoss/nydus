package fixture

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

var (
	blobName     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	blobMetaName = regexp.MustCompile(`^[0-9a-f]{64}\.blob\.meta$`)
)

// Get returns the cached image called name: a layout name builds the Seeded
// corpus, merged-<layout> the overlay of the Layers corpus, huge-<layout>
// the Huge corpus.
func Get(t testing.TB, name string) Image {
	t.Helper()
	if layoutName, ok := strings.CutPrefix(name, MergedPrefix); ok {
		return Merged(t, MustLayout(t, layoutName))
	}

	if layoutName, ok := strings.CutPrefix(name, HugePrefix); ok {
		img := Build(t, Huge, MustLayout(t, layoutName))
		img.Name = name
		return img
	}

	return Build(t, Seeded, MustLayout(t, name))
}

// Build returns the cached image of the named corpus built with layout.
func Build(t testing.TB, corpusName string, layout Layout) Image {
	t.Helper()
	src := Corpus(t, corpusName)

	dir := cached(t, "image", corpusName+"-"+layout.Name, imageKey(t, corpusName, layout), func(t testing.TB, dir string) {
		BuildInto(t, filepath.Join(dir, "blobs"), filepath.Join(dir, "image.bootstrap"), src, layout)
	})

	want := tree(t, corpusName)
	if layout.Tar {
		want = fstest.TarView(want)
	}

	return Image{
		Name:      layout.Name,
		Layout:    layout,
		Corpus:    corpusName,
		Bootstrap: filepath.Join(dir, "image.bootstrap"),
		BlobDir:   filepath.Join(dir, "blobs"),
		Blobs:     blobsIn(t, filepath.Join(dir, "blobs")),
		Source:    src,
		Want:      want,
	}
}

// Merged returns the cached merged image of the Layers corpus, each layer
// built with layout.
func Merged(t testing.TB, layout Layout) Image {
	t.Helper()
	layers := LayerDirs(t)
	var blobs []string

	dir := cached(t, "image", MergedPrefix+layout.Name, imageKey(t, Layers, layout), func(t testing.TB, dir string) {
		args := []string{"merge", "--bootstrap", filepath.Join(dir, "merged.bootstrap")}
		names := make([]string, 0, len(layers))

		for i, layer := range layers {
			bootstrap := filepath.Join(dir, fmt.Sprintf("layer%d.bootstrap", i+1))
			blob, _ := BuildInto(t, filepath.Join(dir, "blobs"), bootstrap, layer, layout)
			// The order of the blobs is the layer order, which the blob
			// directory listing does not keep.
			args = append(args, blob)
			names = append(names, filepath.Base(blob))
		}

		env.Run(t, env.Nydus(t), args...)

		if err := os.WriteFile(filepath.Join(dir, "layers"), []byte(strings.Join(names, "\n")), 0o644); err != nil {
			t.Fatalf("write layer list: %v", err)
		}
	})

	list, err := os.ReadFile(filepath.Join(dir, "layers"))
	if err != nil {
		t.Fatalf("read layer list: %v", err)
	}

	for _, name := range strings.Split(string(list), "\n") {
		blobs = append(blobs, filepath.Join(dir, "blobs", name))
	}

	layerTrees := layerTrees(t)

	if layout.Tar {
		for i := range layerTrees {
			layerTrees[i] = fstest.TarView(layerTrees[i])
		}
	}

	return Image{
		Name:      MergedPrefix + layout.Name,
		Layout:    layout,
		Corpus:    Layers,
		Bootstrap: filepath.Join(dir, "merged.bootstrap"),
		BlobDir:   filepath.Join(dir, "blobs"),
		Blobs:     blobs,
		Merged:    true,
		Want:      fstest.Overlay(layerTrees...),
	}
}

// imageKey identifies a cached image: the builder, the corpus generators,
// the corpus and the layout.
func imageKey(t testing.TB, corpusName string, layout Layout) string {
	t.Helper()
	return strings.Join(append([]string{fileHash(t, env.Nydus(t)), sourceHash(t), corpusName, layout.Name}, layout.Args...), "\x00")
}

// BuildImage builds src with layout into dir, a directory the test owns,
// and returns the image with its recorded tree. It is for datasets a test
// generates itself; Build serves the shared corpora from the cache.
func BuildImage(t testing.TB, dir, src string, layout Layout) Image {
	t.Helper()
	bootstrap := filepath.Join(dir, "image.bootstrap")
	blobDir := filepath.Join(dir, "blobs")
	blob, _ := BuildInto(t, blobDir, bootstrap, src, layout)

	return Image{
		Name:      layout.Name,
		Layout:    layout,
		Corpus:    filepath.Base(src),
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     []string{blob},
		Source:    src,
		Want:      fstest.ScanSource(t, src),
	}
}

// BuildTar streams the tar at r through `nydus build --source-type tar`
// with layout into blobDir, writing bootstrap, and returns the new blob and
// the builder's output. It asserts the builder's output contract as BuildInto
// does.
func BuildTar(t testing.TB, blobDir, bootstrap string, r io.Reader, layout Layout) (blob, output string) {
	t.Helper()
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", blobDir, err)
	}

	before := ListDir(t, blobDir)
	args := append([]string{"build", "--blob-dir", blobDir, "--bootstrap", bootstrap}, layout.Args...)
	cmd := env.Command(t, env.Nydus(t), append(args, "--source-type", "tar", "/dev/stdin")...)
	cmd.Stdin = r

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nydus %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return newBlob(t, blobDir, before, layout), string(out)
}

// BuildInto runs `nydus build` of src with layout into blobDir, writing
// bootstrap, and returns the new blob and the builder's output. It asserts
// the builder's output contract: exactly one new blob named by its SHA256,
// with a blob meta unless the layout is native. A tar layout streams an OCI
// layer tarball of src through BuildTar.
func BuildInto(t testing.TB, blobDir, bootstrap, src string, layout Layout) (blob, output string) {
	t.Helper()
	if layout.Tar {
		pr, pw := io.Pipe()
		// A write error fails the read end and so the build; closing the
		// read end unblocks the writer when the builder stops reading early.
		go func() { _ = pw.CloseWithError(fstest.WriteTar(pw, src)) }()

		defer func() { _ = pr.Close() }()

		return BuildTar(t, blobDir, bootstrap, pr, layout)
	}

	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", blobDir, err)
	}

	before := ListDir(t, blobDir)
	args := append([]string{"build", "--blob-dir", blobDir, "--bootstrap", bootstrap}, layout.Args...)

	out := env.Run(t, env.Nydus(t), append(args, src)...)

	return newBlob(t, blobDir, before, layout), out
}

// newBlob asserts the builder's output contract against the files added to
// blobDir since before: exactly one blob named by its SHA256, with a blob
// meta unless the layout is native. It returns the blob's path.
func newBlob(t testing.TB, blobDir string, before map[string]bool, layout Layout) string {
	t.Helper()
	var blobs, metas []string

	for name := range ListDir(t, blobDir) {
		if before[name] {
			continue
		}

		switch {
		case blobName.MatchString(name):
			blobs = append(blobs, name)

		case blobMetaName.MatchString(name):
			metas = append(metas, name)

		default:
			t.Fatalf("unexpected build output %s in %s", name, blobDir)
		}
	}

	if len(blobs) != 1 {
		t.Fatalf("expected exactly one new blob in %s, got %v", blobDir, blobs)
	}

	blob := filepath.Join(blobDir, blobs[0])
	if got := fileHash(t, blob); got != blobs[0] {
		t.Fatalf("blob %s is not named by its SHA256 %s", blob, got)
	}

	switch {
	case layout.Native && len(metas) != 0:
		t.Fatalf("native layout %s wrote blob meta %v", layout.Name, metas)

	case !layout.Native && (len(metas) != 1 || metas[0] != blobs[0]+".blob.meta"):
		t.Fatalf("layout %s: expected the blob meta of %s, got %v", layout.Name, blobs[0], metas)
	}

	return blob
}

// PackTar streams the tar at r through `nydus build --source-type tar` into
// dir/layer.blob with the arguments nydusify passes, and returns the blob as
// an image to mount in Blob mode; an empty compressor is zstd and a zero
// chunk size 2 MiB.
func PackTar(t testing.TB, r io.Reader, dir, compressor string, chunkSize uint32) (Image, error) {
	t.Helper()
	if compressor == "" {
		compressor = "zstd"
	}

	if chunkSize == 0 {
		chunkSize = 2 << 20
	}

	blob := filepath.Join(dir, "layer.blob")

	cmd := env.Command(t, env.Nydus(t), "build", "/dev/stdin", "--source-type", "tar", "--blob", blob,
		"--chunk-size", strconv.FormatUint(uint64(chunkSize), 10), "--compressor", compressor, "--log-level", "warn")

	cmd.Stdin = r
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Image{}, fmt.Errorf("nydus build: %w: %s", err, stderr.Bytes())
	}

	return Image{Name: "tar-layer", BlobDir: dir, Blobs: []string{blob}}, nil
}

func blobsIn(t testing.TB, dir string) []string {
	t.Helper()
	var blobs []string

	for name := range ListDir(t, dir) {
		if blobName.MatchString(name) {
			blobs = append(blobs, filepath.Join(dir, name))
		}
	}

	return blobs
}

// ListDir returns the names of the regular files in dir.
func ListDir(t testing.TB, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	names := make(map[string]bool, len(entries))

	for _, e := range entries {
		if e.Type().IsRegular() {
			names[e.Name()] = true
		}
	}

	return names
}
