package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// TestBlobMount builds the standard corpus at two chunk sizes and diffs the
// mount of the self-contained blob, of the bootstrap over the blob directory
// and of the bootstrap with a persistent chunk cache against the corpus.
func TestBlobMount(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")

	for _, chunkSize := range []int{4096, 16384} {
		t.Run(fmt.Sprintf("chunk size %d", chunkSize), func(t *testing.T) {
			workDir := t.TempDir()
			corpusDir := filepath.Join(workDir, "corpus")
			bootstrap := filepath.Join(workDir, "test.bootstrap")
			blobDir := filepath.Join(workDir, "blobs")
			cacheDir := filepath.Join(workDir, "cache")
			mountpoint := filepath.Join(workDir, "mnt")

			t.Log("Generating corpus...")
			standard := corpus.MakeStandardCorpus(t, corpusDir)
			standard.CreateUnixSocket(t, "special/socket")

			t.Log("Building blob and mounting it directly...")
			blob := util.BuildImage(t, nydusBin, bootstrap, blobDir, corpusDir, chunkSize)
			util.CheckImage(t, nydusBin, "--blob", blob)
			util.CheckImage(t, nydusBin, "--bootstrap", bootstrap, "--blob-dir", blobDir)
			func() {
				unmount := util.MountNydusBlob(t, nydusBin, blob, mountpoint)
				defer unmount()
				util.CheckDirectoryEqual(t, corpusDir, mountpoint, true)
			}()

			// Mount the bootstrap over the blob directory, then again with a
			// persistent chunk cache.
			func() {
				unmount := util.MountNydusBootstrap(t, nydusBin, bootstrap, blobDir, "", mountpoint)
				defer unmount()
				util.CheckDirectoryEqual(t, corpusDir, mountpoint, true)
			}()
			func() {
				unmount := util.MountNydusBootstrap(t, nydusBin, bootstrap, blobDir, cacheDir, mountpoint)
				defer unmount()
				util.CheckDirectoryEqual(t, corpusDir, mountpoint, true)
				verifyChunkCacheFiles(t, cacheDir, blob)
			}()
		})
	}
}

// verifyChunkCacheFiles checks the chunk cache holds exactly one .blob.data,
// .blob.meta and .group.map file per blob, named by its digest.
func verifyChunkCacheFiles(t *testing.T, cacheDir string, blobs ...string) {
	t.Helper()
	entries, err := os.ReadDir(cacheDir)
	assert.NoError(t, err)

	var blobDataCount, groupMapCount, blobMetaCount int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		switch name := entry.Name(); {
		case strings.HasSuffix(name, ".blob.data"):
			blobDataCount++
		case strings.HasSuffix(name, ".group.map"):
			groupMapCount++
		case strings.HasSuffix(name, ".blob.meta"):
			blobMetaCount++
		}
	}

	assert.Equal(t, len(blobs), blobDataCount, "unexpected cached blob.data count")
	assert.Equal(t, len(blobs), groupMapCount, "unexpected cached group map count")
	assert.Equal(t, len(blobs), blobMetaCount, "unexpected cached blob_meta count")

	for _, blob := range blobs {
		digest := util.Sha256File(t, blob)
		assert.FileExists(t, filepath.Join(cacheDir, digest+".blob.data"))
		assert.FileExists(t, filepath.Join(cacheDir, digest+".blob.meta"))
		assert.FileExists(t, filepath.Join(cacheDir, digest+".group.map"))
	}
}
