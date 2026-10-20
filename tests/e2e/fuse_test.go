package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
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

// TestBlobIntegrity corrupts one byte of a blob's data region and reads the
// file stored there: the blob meta carries a CRC per chunk group that every
// decode checks by default, so the read fails instead of serving the
// corruption; with the check skipped the corruption is served. The image is
// built without compression, so the corruption survives decoding.
func TestBlobIntegrity(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	workDir := t.TempDir()
	source := filepath.Join(workDir, "source")
	blobDir := filepath.Join(workDir, "blobs")
	bootstrap := filepath.Join(workDir, "image.boot")
	assert.NoError(t, os.MkdirAll(source, 0o755))
	util.WriteRandomFile(t, filepath.Join(source, "data.bin"), 1<<20)
	blob := util.BuildImage(t, nydusBin, bootstrap, blobDir, source, 1<<20, "--compressor", "none")

	// Flip a byte well inside the data region, which starts the full blob.
	f, err := os.OpenFile(blob, os.O_RDWR, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	var b [1]byte
	_, err = f.ReadAt(b[:], 4096)
	assert.NoError(t, err)
	b[0] ^= 0xff
	_, err = f.WriteAt(b[:], 4096)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())

	corrupted, err := os.ReadFile(filepath.Join(source, "data.bin"))
	assert.NoError(t, err)
	corrupted[4096] ^= 0xff

	skip := true
	tests := []struct {
		name   string
		skip   *bool
		expect func(t *testing.T, data []byte, err error, logDir string)
	}{
		{
			name: "checksums verified, the default",
			expect: func(t *testing.T, _ []byte, err error, logDir string) {
				assert := assert.New(t)
				assert.ErrorIs(err, unix.EIO)
				assert.Eventually(func() bool {
					return strings.Contains(util.ReadLogs(logDir), "crc32 mismatch")
				}, 10*time.Second, 200*time.Millisecond, "the corruption was not caught by the chunk group crc")
			},
		},
		{
			name: "checksums skipped",
			skip: &skip,
			expect: func(t *testing.T, data []byte, err error, logDir string) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(corrupted, data, "the corruption was not served as is")
				assert.NotContains(util.ReadLogs(logDir), "crc32 mismatch")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			dir := t.TempDir()
			config := util.NewLocalBackendConfig(blobDir, filepath.Join(dir, "cache"), "none")
			config.Storage.SkipVerifyChecksums = tc.skip
			config.Write(t, filepath.Join(dir, "nydus.yaml"))
			mountpoint := filepath.Join(dir, "mnt")
			logDir := filepath.Join(dir, "logs")
			assert.NoError(os.MkdirAll(mountpoint, 0o755))
			cmd := exec.Command(nydusBin, "fuse", "--bootstrap", bootstrap, "--config", filepath.Join(dir, "nydus.yaml"), "--mountpoint", mountpoint, "--log-dir", logDir)
			t.Cleanup(util.MountFuse(t, cmd, mountpoint, "nydus fuse"))

			data, err := os.ReadFile(filepath.Join(mountpoint, "data.bin"))
			tc.expect(t, data, err, logDir)
		})
	}
}
