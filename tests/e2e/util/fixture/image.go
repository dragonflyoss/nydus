// Package fixture provides the corpora and images every e2e suite reads:
// named source trees and `nydus build` layouts, built once and cached on
// disk across test binaries and runs.
package fixture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

// Image is a built nydus image. Cached images are shared by every test:
// treat every path as read-only, and Copy the image before damaging it.
type Image struct {
	// Name is the layout name, or merged-<layout>.
	Name   string
	Layout Layout
	// Corpus names the corpus the image was built from.
	Corpus    string
	Bootstrap string
	BlobDir   string
	// Blobs are the full data blobs, one per layer, lowest first.
	Blobs  []string
	Merged bool
	// Source is the directory the image was built from; empty for merged
	// images, which reproduce an overlay rather than any one directory.
	Source string
	// Want is the tree every read path of the image must reproduce.
	Want []fstest.Entry
}

// Blob returns the single data blob of an unmerged image, failing t when
// the image has several.
func (img Image) Blob(t testing.TB) string {
	t.Helper()
	if len(img.Blobs) != 1 {
		t.Fatalf("image %s has %d blobs", img.Name, len(img.Blobs))
	}

	return img.Blobs[0]
}

// Compare is how a mount of the image is judged against Want: a merged
// bootstrap keeps each layer's link count, which a group broken by an upper
// layer no longer matches.
func (img Image) Compare() fstest.CompareOptions {
	return fstest.CompareOptions{Nlink: !img.Merged}
}

// FlipByte inverts the byte of path at off, to damage an image a test owns.
func FlipByte(t testing.TB, path string, off int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}

	defer func() { _ = f.Close() }()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatalf("read %s at %d: %v", path, off, err)
	}

	b[0] ^= 0xff
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatalf("write %s at %d: %v", path, off, err)
	}
}

// Copy duplicates img into a directory owned by the test, for tests that
// damage or extend an image.
func Copy(t testing.TB, img Image) Image {
	t.Helper()
	dir := env.WorkDir(t)
	blobDir := filepath.Join(dir, "blobs")
	env.Run(t, "cp", "-a", img.BlobDir, blobDir)
	bootstrap := filepath.Join(dir, filepath.Base(img.Bootstrap))
	env.Run(t, "cp", "-a", img.Bootstrap, bootstrap)
	out := img
	out.Bootstrap = bootstrap
	out.BlobDir = blobDir

	out.Blobs = nil
	for _, b := range img.Blobs {
		out.Blobs = append(out.Blobs, filepath.Join(blobDir, filepath.Base(b)))
	}

	return out
}
