package cache

import (
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestCorrupt(t *testing.T) {
	t.Parallel()
	w := setup(t)

	damages := []struct {
		name   string
		damage func(t *testing.T, cache cacheDir)
	}{
		{"DataBytes", func(t *testing.T, cache cacheDir) {
			warm := cache.mount(t, w.lowerImage)
			warm.mustRead(t, "shared.bin", w.want["shared.bin"])
			warm.Unmount()

			if n := cache.flipData(t, w.sharedBlob); !assert.NotZero(t, n) {
				t.FailNow()
			}
		}},
		{"MapBits", func(t *testing.T, cache cacheDir) {
			warm := cache.mount(t, w.lowerImage, fetchSize(64<<10))
			warm.mustReadAt(t, "shared.bin", 0, 4096, w.data["shared.bin"])
			warm.Unmount()

			if n := cache.forgeReady(t, w.sharedBlob); !assert.NotZero(t, n) {
				t.FailNow()
			}
		}},
	}

	for _, d := range damages {
		for _, verify := range []bool{false, true} {
			name := d.name + "Default"

			var edits []func(*mount.Config)
			if verify {
				name = d.name + "Verify"
				edits = append(edits, verifyChecksums)
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()
				cache := newCache(t)
				d.damage(t, cache)
				fresh := cache.mount(t, w.lowerImage, edits...)
				fresh.checkRead(t, "shared.bin", w.want["shared.bin"])
			})
		}
	}
}

func TestDeletedDatafile(t *testing.T) {
	t.Parallel()
	w := setup(t)
	want := w.want["shared.bin"]
	cache := newCache(t)
	dataPath := cache.file(w.sharedBlob, mount.CacheDataSuffix)

	old := cache.mount(t, w.lowerImage)
	old.mustRead(t, "shared.bin", want)
	deleted := inode(t, dataPath)

	if err := os.Remove(dataPath); !assert.NoError(t, err) {
		t.FailNow()
	}

	newer := cache.mount(t, w.lowerImage)
	newer.mustReadAt(t, "shared.bin", 0, 4096, w.data["shared.bin"])

	if got := inode(t, dataPath); !assert.NotEqual(t, deleted, got) {
		t.FailNow()
	}

	old.checkRead(t, "shared.bin", want)

	newer.mustRead(t, "shared.bin", want)
}

func TestStaleChunkMapKeepsInode(t *testing.T) {
	t.Parallel()
	w := setup(t)
	cache := newCache(t)
	first := cache.mount(t, w.lowerImage)
	first.mustRead(t, "shared.bin", w.want["shared.bin"])

	groupMap := cache.file(w.sharedBlob, mount.CacheMapSuffix)
	before := inode(t, groupMap)

	if err := os.Remove(cache.file(w.sharedBlob, mount.CacheDataSuffix)); !assert.NoError(t, err) {
		t.FailNow()
	}

	second := cache.mount(t, w.lowerImage)
	second.mustRead(t, "shared.bin", w.want["shared.bin"])
	after := inode(t, groupMap)
	assert.Equal(t, before, after)
}

func verifyChecksums(c *mount.Config) { c.Storage.SkipVerifyChecksums = mount.Ptr(false) }

func fetchSize(n int64) func(*mount.Config) {
	return func(c *mount.Config) { c.Storage.FetchSize = mount.Ptr(n) }
}

func inode(t testing.TB, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); !assert.NoError(t, err) {
		t.FailNow()
	}

	return st.Ino
}
