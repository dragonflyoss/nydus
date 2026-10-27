package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// TestSharedBlobUsesOneCacheEntry checks that two images referencing one blob
// converge on one set of cache files, which is what makes a node running
// many images cheap.
func TestSharedBlobUsesOneCacheEntry(t *testing.T) {
	t.Parallel()
	w := setup(t)
	cacheDir := newCache(t)
	image1 := mountOn(t, w.image1, cacheDir)
	image2 := mountOn(t, w.image2, cacheDir)

	// Touch every blob: file1.bin is only in image1, file3.bin only in
	// image2, and shared.bin is the same blob in both.
	mustRead(t, image1.Path("file1.bin"), w.want["file1.bin"])
	mustRead(t, image2.Path("file3.bin"), w.want["file3.bin"])
	mustReadConcurrently(t, []*mount.Mounted{image1, image2}, "shared.bin", w.want["shared.bin"])

	// The cache is keyed by blob, so the shared blob is cached once.
	if _, err := os.Stat(cacheFile(cacheDir, w.keyB, dataSuffix)); err != nil {
		t.Errorf("shared blob's cache data: %v", err)
	}
	data, err := filepath.Glob(filepath.Join(cacheDir, "*"+dataSuffix))
	if err != nil {
		t.Fatalf("list cache: %v", err)
	}
	if len(data) != 3 {
		t.Errorf("cache holds %d data files %v, want one per distinct blob (A, B, C)", len(data), data)
	}
}
