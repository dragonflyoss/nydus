package cache

import (
	"os"
	"testing"
)

// TestStaleChunkMapKeepsInode deletes the cached data behind a live daemon.
// The next daemon must reset the orphaned group map in place: replacing it
// would split the daemons onto two maps, each publishing readiness the other
// never sees.
func TestStaleChunkMapKeepsInode(t *testing.T) {
	t.Parallel()
	w := setup(t)
	cacheDir := newCache(t)
	first := mountOn(t, w.image1, cacheDir)
	mustRead(t, first.Path("shared.bin"), w.want["shared.bin"])

	groupMap := cacheFile(cacheDir, w.keyB, mapSuffix)
	before := inode(t, groupMap)
	// An external reclaimer removes only the data file.
	if err := os.Remove(cacheFile(cacheDir, w.keyB, dataSuffix)); err != nil {
		t.Fatalf("remove cache data: %v", err)
	}

	second := mountOn(t, w.image1, cacheDir)
	mustRead(t, second.Path("shared.bin"), w.want["shared.bin"])
	if after := inode(t, groupMap); after != before {
		t.Errorf("group map inode changed from %d to %d: the stale map was replaced, not reset in place", before, after)
	}
}
