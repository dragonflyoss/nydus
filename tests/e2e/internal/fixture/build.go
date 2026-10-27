package fixture

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

var (
	blobName     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	blobMetaName = regexp.MustCompile(`^[0-9a-f]{64}\.blob\.meta$`)
)

// Get returns the cached image called name: a layout name builds the Seeded
// corpus, merged-<layout> the overlay of the Layers corpus, huge-<layout>
// the Huge corpus.
func Get(t env.TB, name string) Image {
	t.Helper()
	if layoutName, ok := strings.CutPrefix(name, MergedPrefix); ok {
		return Merged(t, mustLayout(t, layoutName))
	}
	if layoutName, ok := strings.CutPrefix(name, HugePrefix); ok {
		img := Build(t, Huge, mustLayout(t, layoutName))
		img.Name = name
		return img
	}
	return Build(t, Seeded, mustLayout(t, name))
}

func mustLayout(t env.TB, name string) Layout {
	t.Helper()
	l, err := LayoutByName(name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return l
}

// Build returns the cached image of the named corpus built with layout.
func Build(t env.TB, corpusName string, layout Layout) Image {
	t.Helper()
	src := Corpus(t, corpusName)
	nydus := env.Nydus(t)
	key := strings.Join(append([]string{fileHash(t, nydus), sourceHash(t), corpusName, layout.Name}, layout.Args...), "\x00")
	dir := cached(t, "image", corpusName+"-"+layout.Name, key, func(dir string) {
		BuildInto(t, filepath.Join(dir, "blobs"), filepath.Join(dir, "image.bootstrap"), src, layout)
	})

	want := Tree(t, corpusName)
	if layout.Tar {
		want = oracle.TarView(want)
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
func Merged(t env.TB, layout Layout) Image {
	t.Helper()
	layers := LayerDirs(t)
	nydus := env.Nydus(t)
	key := strings.Join(append([]string{fileHash(t, nydus), sourceHash(t), Layers, layout.Name}, layout.Args...), "\x00")
	var blobs []string
	dir := cached(t, "image", MergedPrefix+layout.Name, key, func(dir string) {
		args := []string{"merge", "--bootstrap", filepath.Join(dir, "merged.bootstrap")}
		for i, layer := range layers {
			bootstrap := filepath.Join(dir, fmt.Sprintf("layer%d.bootstrap", i+1))
			blob, _ := BuildInto(t, filepath.Join(dir, "blobs"), bootstrap, layer, layout)
			// The order of the blobs is the layer order, which the blob
			// directory listing does not keep.
			args = append(args, blob)
		}
		Run(t, nydus, args...)
		var names []string
		for _, blob := range args[3:] {
			names = append(names, filepath.Base(blob))
		}
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

	layerTrees := LayerTrees(t)
	if layout.Tar {
		for i := range layerTrees {
			layerTrees[i] = oracle.TarView(layerTrees[i])
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
		Want:      oracle.Overlay(layerTrees...),
	}
}

// BuildInto runs `nydus build` of src with layout into blobDir, writing
// bootstrap, and returns the new blob and the builder's output. It asserts
// the builder's output contract: exactly one new blob named by its SHA256,
// with a blob meta unless the layout is native. A tar layout streams an OCI
// layer tarball of src through stdin.
func BuildInto(t env.TB, blobDir, bootstrap, src string, layout Layout) (blob, output string) {
	t.Helper()
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", blobDir, err)
	}
	before := listDir(t, blobDir)
	nydus := env.Nydus(t)
	args := append([]string{"build", "--blob-dir", blobDir, "--bootstrap", bootstrap}, layout.Args...)

	var out []byte
	var err error
	if layout.Tar {
		pr, pw := io.Pipe()
		written := make(chan error, 1)
		go func() {
			err := oracle.WriteTar(pw, src)
			_ = pw.CloseWithError(err)
			written <- err
		}()
		cmd := exec.Command(nydus, append(args, "--source-type", "tar", "/dev/stdin")...)
		cmd.Stdin = pr
		out, err = cmd.CombinedOutput()
		_ = pr.CloseWithError(io.ErrClosedPipe)
		if writeErr := <-written; err == nil && writeErr != nil {
			err = writeErr
		}
	} else {
		out, err = exec.Command(nydus, append(args, src)...).CombinedOutput()
	}
	if err != nil {
		t.Fatalf("nydus %s %s: %v\n%s", strings.Join(args, " "), src, err, out)
	}

	var blobs, metas []string
	for name := range listDir(t, blobDir) {
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
	blob = filepath.Join(blobDir, blobs[0])
	if got := fileHash(t, blob); got != blobs[0] {
		t.Fatalf("blob %s is not named by its SHA256 %s", blob, got)
	}
	switch {
	case layout.Native && len(metas) != 0:
		t.Fatalf("native layout %s wrote blob meta %v", layout.Name, metas)
	case !layout.Native && (len(metas) != 1 || metas[0] != blobs[0]+".blob.meta"):
		t.Fatalf("layout %s: expected the blob meta of %s, got %v", layout.Name, blobs[0], metas)
	}
	return blob, string(out)
}

// Copy duplicates img into a directory owned by the test, for tests that
// damage or extend an image.
func Copy(t env.TB, img Image) Image {
	t.Helper()
	dir := env.WorkDir(t)
	blobDir := filepath.Join(dir, "blobs")
	Run(t, "cp", "-a", img.BlobDir, blobDir)
	bootstrap := filepath.Join(dir, filepath.Base(img.Bootstrap))
	Run(t, "cp", "-a", img.Bootstrap, bootstrap)
	out := img
	out.Bootstrap = bootstrap
	out.BlobDir = blobDir
	out.Blobs = nil
	for _, b := range img.Blobs {
		out.Blobs = append(out.Blobs, filepath.Join(blobDir, filepath.Base(b)))
	}
	return out
}

// Run runs bin with args and returns its combined output, failing the test
// with that output on a non-zero exit.
func Run(t env.TB, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, out)
	}
	return string(out)
}

func blobsIn(t env.TB, dir string) []string {
	t.Helper()
	var blobs []string
	for name := range listDir(t, dir) {
		if blobName.MatchString(name) {
			blobs = append(blobs, filepath.Join(dir, name))
		}
	}
	return blobs
}

func listDir(t env.TB, dir string) map[string]bool {
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
