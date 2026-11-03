package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	t.Parallel()
	for _, name := range fixture.MergeLayouts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layout := fixture.MustLayout(t, name)
			dir := env.WorkDir(t)
			blobDir := filepath.Join(dir, "blobs")
			merged := filepath.Join(dir, "merged.bootstrap")

			args := []string{"merge", "--bootstrap", merged}
			var blobs []string

			for i, layer := range fixture.LayerDirs(t) {
				bootstrap := filepath.Join(dir, fmt.Sprintf("layer%d.bootstrap", i+1))
				blob, _ := fixture.BuildInto(t, blobDir, bootstrap, layer, layout)
				blobs = append(blobs, blob)
			}

			env.Run(t, env.Nydus(t), append(args, blobs...)...)

			tags, err := erofs.DeviceTags(merged)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			var want []string

			for _, blob := range blobs {
				want = append(want, filepath.Base(blob))
			}

			assert.Equal(t, want, tags)

			if erofs.FsckDecodes(t, layout.Compressor()) {
				erofs.Fsck(t, merged, blobDir)
			}

			requireVerified(t, merged, blobDir, blobs)

			cached := fixture.Merged(t, layout)
			if !assert.Equal(t, fstest.FileSHA256(t, cached.Bootstrap), fstest.FileSHA256(t, merged)) {
				t.FailNow()
			}

			img := cached
			img.Bootstrap, img.BlobDir, img.Blobs = merged, blobDir, blobs
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
			fstest.VerifyMount(t, m.Root, img.Want, img.Compare())

			if !layout.Native {
				requireCacheArtifacts(t, m.CacheDir, blobs)
			}

			fstest.CompareTree(t, withMergedNlink(img.Want), fstest.ScanTree(t, m.Root), fstest.CompareOptions{Nlink: true})
		})
	}
}

func withMergedNlink(entries []fstest.Entry) []fstest.Entry {
	members := map[fstest.Bytes]uint64{}

	for _, entry := range entries {
		if entry.Link != "" {
			members[entry.Link]++
		}
	}

	out := make([]fstest.Entry, len(entries))
	copy(out, entries)

	for i := range out {
		if out[i].Type == fstest.TypeDir {
			continue
		}

		out[i].Nlink = 1
		if out[i].Link != "" {
			out[i].Nlink = members[out[i].Link]
		}
	}

	return out
}

func requireCacheArtifacts(t testing.TB, cacheDir string, blobs []string) {
	t.Helper()
	entries, err := os.ReadDir(cacheDir)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	counts := map[string]int{}

	for _, entry := range entries {
		for _, suffix := range []string{mount.CacheDataSuffix, mount.CacheMapSuffix, mount.CacheMetaSuffix} {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
				counts[suffix]++
			}
		}
	}

	for _, suffix := range []string{mount.CacheDataSuffix, mount.CacheMapSuffix, mount.CacheMetaSuffix} {
		if !assert.Equal(t, len(blobs), counts[suffix]) {
			t.FailNow()
		}

		for _, blob := range blobs {
			assert.FileExists(t, filepath.Join(cacheDir, filepath.Base(blob)+suffix))
		}
	}
}
