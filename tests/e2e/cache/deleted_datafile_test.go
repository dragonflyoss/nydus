package cache

import (
	"os"
	"testing"
)

// TestDeletedDatafile deletes a cache data file while a daemon has it open.
// That daemon keeps a descriptor to the deleted inode; a daemon started
// afterwards gets a new data file and resets the shared group map. Neither
// may return wrong bytes: the old daemon must stop publishing readiness for
// groups it writes into the deleted inode, or the new daemon reads holes.
func TestDeletedDatafile(t *testing.T) {
	t.Parallel()
	w := setup(t)
	want := w.want["shared.bin"]
	cacheDir := newCache(t)
	dataPath := cacheFile(cacheDir, w.keyB, dataSuffix)

	old := mountOn(t, w.image1, cacheDir)
	mustRead(t, old.Path("shared.bin"), want)
	deleted := inode(t, dataPath)
	if err := os.Remove(dataPath); err != nil {
		t.Fatalf("remove cache data: %v", err)
	}

	// The new daemon's first read opens the cache: it finds the map
	// orphaned, resets it and fills one window into a new data file.
	newer := mountOn(t, w.image1, cacheDir)
	mustReadAt(t, newer.Path("shared.bin"), 0, 4096, w.data["shared.bin"])
	if got := inode(t, dataPath); got == deleted {
		t.Fatalf("new daemon reopened the deleted data file inode %d", got)
	}

	// The old daemon may reject the unlinked cache inode, but must never
	// publish its bytes as ready in the replacement file.
	checkRead(t, old.Path("shared.bin"), want)

	mustRead(t, newer.Path("shared.bin"), want)
}
