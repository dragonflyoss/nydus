package integration

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/lepton/tests/integration/texture"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const leptonRunErofsCompatEnv = "LEPTONFS_RUN_EROFS_COMPAT"

func TestBlobMountE2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	for _, chunkSize := range []int{4096, 16384} {
		chunkSize := chunkSize
		t.Run(fmt.Sprintf("ChunkSize%d", chunkSize), func(t *testing.T) {
			tmpDir := t.TempDir()
			corpusDir := filepath.Join(tmpDir, "corpus")
			bootstrapPath := filepath.Join(tmpDir, "test.bootstrap")
			blobDir := filepath.Join(tmpDir, "blobs")
			cacheDir := filepath.Join(tmpDir, "cache")
			mntDir := filepath.Join(tmpDir, "mnt")

			t.Log("Generating corpus...")
			corpus := texture.MakeStandardCorpus(t, corpusDir)
			corpus.CreateUnixSocket(t, "special/socket")

			t.Log("Building blob and mounting it directly...")
			leptonBin := mustLookupExecutable(t, "lepton")
			blobPath := buildLeptonFSImageToDir(t, leptonBin, bootstrapPath, blobDir, corpusDir, chunkSize)
			logLeptonCheckOutput(t, leptonBin, "--blob", blobPath)
			logLeptonCheckOutput(t, leptonBin, "--bootstrap", bootstrapPath, "--blob-dir", blobDir)
			func() {
				unmount := mountLepton(t, leptonBin, "", blobPath, mntDir)
				defer unmount()
				verifyMountedTree(t, corpusDir, mntDir)
			}()

			func() {
				unmount := mountLeptonBootstrap(t, leptonBin, bootstrapPath, blobDir, mntDir)
				defer unmount()
				verifyMountedTree(t, corpusDir, mntDir)
			}()

			func() {
				unmount := mountLeptonBootstrapWithCache(t, leptonBin, bootstrapPath, blobDir, cacheDir, mntDir)
				defer unmount()
				verifyMountedTree(t, corpusDir, mntDir)
				verifyBlobCacheArtifacts(t, cacheDir, blobPath)
			}()
		})
	}
}

func TestMergedMountE2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	tmpDir := t.TempDir()
	layer1Dir := filepath.Join(tmpDir, "layer1")
	layer2Dir := filepath.Join(tmpDir, "layer2")
	layer3Dir := filepath.Join(tmpDir, "layer3")
	expectedDir := filepath.Join(tmpDir, "expected")
	mountpoint := filepath.Join(tmpDir, "mnt")
	prepareMergedE2ECorpora(t, layer1Dir, layer2Dir, layer3Dir, expectedDir)

	leptonBin := mustLookupExecutable(t, "lepton")
	blobDir := filepath.Join(tmpDir, "blobs")
	layer1Bootstrap := filepath.Join(tmpDir, "layer1.bootstrap")
	layer2Bootstrap := filepath.Join(tmpDir, "layer2.bootstrap")
	layer3Bootstrap := filepath.Join(tmpDir, "layer3.bootstrap")
	mergedBootstrap := filepath.Join(tmpDir, "merged.bootstrap")
	cacheDir := filepath.Join(tmpDir, "cache")

	layer1Blob := buildLeptonFSImageToDir(t, leptonBin, layer1Bootstrap, blobDir, layer1Dir, 4096)
	layer2Blob := buildLeptonFSImageToDir(t, leptonBin, layer2Bootstrap, blobDir, layer2Dir, 4096)
	layer3Blob := buildLeptonFSImageToDir(t, leptonBin, layer3Bootstrap, blobDir, layer3Dir, 4096)
	logLeptonCheckOutput(t, leptonBin, "--bootstrap", layer1Bootstrap, "--blob-dir", blobDir)

	mergeLeptonBootstrap(
		t,
		leptonBin,
		mergedBootstrap,
		layer1Blob,
		layer2Blob,
		layer3Blob,
	)
	logLeptonCheckOutput(t, leptonBin, "--bootstrap", mergedBootstrap, "--blob-dir", blobDir)

	func() {
		unmount := mountLeptonBootstrap(t, leptonBin, mergedBootstrap, blobDir, mountpoint)
		defer unmount()
		printMergeDebugPaths(t, layer1Dir, layer2Dir, layer3Dir, mountpoint)

		verifyMountedTree(t, expectedDir, mountpoint)
		verifyWhiteoutResults(t, mountpoint)
	}()

	func() {
		unmount := mountLeptonBootstrapWithCache(t, leptonBin, mergedBootstrap, blobDir, cacheDir, mountpoint)
		defer unmount()

		verifyMountedTree(t, expectedDir, mountpoint)
		verifyWhiteoutResults(t, mountpoint)
		verifyBlobCacheArtifacts(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)
		verifyMergedMountMatchesErofsFuseWhenEnabled(
			t,
			mergedBootstrap,
			mountpoint,
			cachedBlobDataDevicesForBlobs(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)...,
		)
		pauseMergeDebugIfRequested(t, mountpoint)
	}()
}

func verifyMergedMountMatchesErofsFuseWhenEnabled(
	t *testing.T,
	mergedBootstrap string,
	leptonMountpoint string,
	blobs ...string,
) {
	t.Helper()
	if os.Getenv(leptonRunErofsCompatEnv) != "1" {
		t.Logf("Skipping erofsfuse compatibility step; set %s=1 to enable", leptonRunErofsCompatEnv)
		return
	}

	setupCErofsfuse(t)
	cErofsFuseBin := mustLookupCErofsFuse(t)
	erofsMountpoint := filepath.Join(t.TempDir(), "erofsfuse-mnt")
	unmount := mountCErofsFuse(t, cErofsFuseBin, mergedBootstrap, erofsMountpoint, blobs...)
	defer unmount()

	verifyMountedTreeAgainstErofsCompat(t, erofsMountpoint, leptonMountpoint)
}

func cachedBlobDataDevicesForBlobs(t *testing.T, cacheDir string, blobs ...string) []string {
	t.Helper()

	// erofsfuse consumes plain external devices. Lepton builds zstd-compressed
	// full blobs, so compat mode must use the cache files populated by lepton fuse.
	devices := make([]string, 0, len(blobs))
	for _, blob := range blobs {
		blobID := fullBlobDigest(t, blob)
		cachedBlob := filepath.Join(cacheDir, blobID+".blob.data")
		require.FileExists(t, cachedBlob, "cached uncompressed blob data should exist after lepton cached mount")
		devices = append(devices, cachedBlob)
	}
	return devices
}

func fullBlobDigest(t *testing.T, blob string) string {
	t.Helper()

	data, err := os.ReadFile(blob)
	require.NoError(t, err)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func prepareMergedE2ECorpora(t *testing.T, layer1Dir, layer2Dir, layer3Dir, expectedDir string) {
	t.Helper()

	base := texture.MakeStandardCorpus(t, layer1Dir)
	addMergeBaseEntries(t, base)

	layer2 := texture.NewCorpus(t, layer2Dir)
	layer2.CreateFile(t, "merge/.wh.remove.txt", nil)
	layer2.CreateFile(t, "merge/middle.txt", []byte("middle-from-layer2"))
	layer2.CreateFile(t, "merge/dir/mid.txt", []byte("mid-from-layer2"))
	layer2.CreateFile(t, "xattrs/merged_upper", []byte("merged upper xattr\n"))
	layer2.SetXattr(t, "xattrs/merged_upper", "user.merged", []byte("layer2"))
	layer2.CreateFile(t, "xattrs/merged_override", []byte("merged override from layer2\n"))
	layer2.SetXattr(t, "xattrs/merged_override", "user.layer", []byte("layer2"))
	layer2.SetXattr(t, "xattrs/merged_override", "user.extra", []byte("layer2-extra"))
	layer2.CreateDir(t, "xattrs/merged_dir")
	layer2.SetXattr(t, "xattrs/merged_dir", "user.dir.merged", []byte("layer2-dir"))
	layer2.CreateSymlink(t, "symlinks/merged_link", "../files/tiny_2b")
	layer2.CreateFIFO(t, "special/upper_fifo")
	layer2.CreateFile(t, "upperhard/original", []byte("upper shared"))
	layer2.CreateHardlink(t, "upperhard/link1", "upperhard/original")
	layer2.CreateSymlink(t, "merge/type_file_to_link", "../files/tiny_2b")

	layer3 := texture.NewCorpus(t, layer3Dir)
	layer3.CreateFile(t, "files/tiny_2b", []byte("ok"))
	layer3.CreateFile(t, "merge/lower.txt", []byte("lower-v3"))
	layer3.CreateFile(t, "merge/type_link_to_file", []byte("layer3-file-wins"))
	layer3.CreateFile(t, "merge/dir/.wh.base.txt", nil)
	layer3.CreateFile(t, "merge/dir/top.txt", []byte("top-from-layer3"))
	layer3.CreateFile(t, "merge/opq/.wh..wh..opq", nil)
	layer3.CreateFile(t, "merge/opq/new.txt", []byte("new-from-layer3"))

	cloneTreePreservingLinks(t, layer1Dir, expectedDir)
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "xattrs/merged_upper")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "xattrs/merged_override")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "xattrs/merged_dir")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "symlinks/merged_link")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "special/upper_fifo")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "upperhard")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "merge/type_file_to_link")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/type_link_to_file")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "files/tiny_2b")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/lower.txt")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "merge/middle.txt")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "merge/dir/mid.txt")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/dir/top.txt")

	removeExpectedPath(t, expectedDir, "merge/remove.txt")
	removeExpectedPath(t, expectedDir, "merge/dir/base.txt")
	removeExpectedPath(t, expectedDir, "merge/opq")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/opq/new.txt")
	overlayExpectedDirectoryMetadata(t, layer2Dir, expectedDir)
	overlayExpectedDirectoryMetadata(t, layer3Dir, expectedDir)
}

func cloneTreePreservingLinks(t *testing.T, srcDir, dstDir string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(dstDir))
	require.NoError(t, os.MkdirAll(dstDir, 0755))
	copySource := srcDir + string(os.PathSeparator) + "."
	out, err := exec.Command("cp", "-a", copySource, dstDir).CombinedOutput()
	require.NoError(t, err, "cp -a failed: %s", string(out))
}

func copyPathPreservingMetadata(t *testing.T, srcRoot, dstRoot, rel string) {
	t.Helper()

	srcPath := filepath.Join(srcRoot, rel)
	dstPath := filepath.Join(dstRoot, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(dstPath), 0755))
	require.NoError(t, os.RemoveAll(dstPath))
	out, err := exec.Command("cp", "-a", srcPath, dstPath).CombinedOutput()
	require.NoError(t, err, "cp -a failed: %s", string(out))
}

func overlayExpectedDirectoryMetadata(t *testing.T, srcRoot, dstRoot string) {
	t.Helper()

	err := filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}

		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		return copyDirectoryMetadata(path, filepath.Join(dstRoot, rel))
	})
	require.NoError(t, err)
}

func copyDirectoryMetadata(srcPath, dstPath string) error {
	srcInfo, err := os.Lstat(srcPath)
	if err != nil {
		return err
	}

	dstInfo, err := os.Lstat(dstPath)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() || !dstInfo.IsDir() {
		return nil
	}

	srcStat := srcInfo.Sys().(*syscall.Stat_t)
	if err := os.Chmod(dstPath, srcInfo.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chown(dstPath, int(srcStat.Uid), int(srcStat.Gid)); err != nil {
		return err
	}
	if err := os.Chtimes(
		dstPath,
		time.Unix(srcStat.Atim.Sec, srcStat.Atim.Nsec),
		time.Unix(srcStat.Mtim.Sec, srcStat.Mtim.Nsec),
	); err != nil {
		return err
	}

	return syncXattrs(srcPath, dstPath)
}

func syncXattrs(srcPath, dstPath string) error {
	srcNames, err := xattr.List(srcPath)
	if err != nil {
		return err
	}
	dstNames, err := xattr.List(dstPath)
	if err != nil {
		return err
	}

	srcSet := make(map[string]struct{}, len(srcNames))
	for _, name := range srcNames {
		srcSet[name] = struct{}{}
		value, err := xattr.Get(srcPath, name)
		if err != nil {
			return err
		}
		if err := xattr.Set(dstPath, name, value); err != nil {
			return err
		}
	}

	for _, name := range dstNames {
		if _, ok := srcSet[name]; ok {
			continue
		}
		if err := xattr.Remove(dstPath, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

func addMergeBaseEntries(t *testing.T, corpus *texture.Corpus) {
	t.Helper()

	corpus.CreateFile(t, "merge/lower.txt", []byte("lower-v1"))
	corpus.CreateFile(t, "merge/remove.txt", []byte("remove-me"))
	corpus.CreateFile(t, "merge/shared/keep.txt", []byte("shared-from-layer1"))
	corpus.CreateFile(t, "merge/dir/base.txt", []byte("base-from-layer1"))
	corpus.CreateFile(t, "merge/opq/old.txt", []byte("old-from-layer1"))
	corpus.CreateFile(t, "merge/opq/subdir/old_nested.txt", []byte("nested-old-from-layer1"))
	corpus.CreateFile(t, "merge/type_file_to_link", []byte("layer1-regular"))
	corpus.CreateSymlink(t, "merge/type_link_to_file", "../files/tiny_2b")
	corpus.CreateFile(t, "xattrs/merged_override", []byte("merged override from layer1\n"))
	corpus.SetXattr(t, "xattrs/merged_override", "user.layer", []byte("layer1"))
}

func removeExpectedPath(t *testing.T, root, rel string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(filepath.Join(root, rel)))
}

func verifyMountedTree(t *testing.T, srcDir, mntDir string) {
	verifyMountedTreeWithOptions(t, srcDir, mntDir, true)
}

func verifyMountedTreeAgainstErofsCompat(t *testing.T, srcDir, mntDir string) {
	verifyMountedTreeWithOptions(t, srcDir, mntDir, false)
}

func verifyMountedTreeWithOptions(t *testing.T, srcDir, mntDir string, compareMtimeNsec bool) {
	t.Helper()

	t.Run("PathSet", func(t *testing.T) { verifyPathSet(t, srcDir, mntDir) })
	t.Run("PathTypes", func(t *testing.T) { verifyPathTypes(t, srcDir, mntDir) })
	t.Run("FileContent", func(t *testing.T) { verifyFileContent(t, srcDir, mntDir) })
	t.Run("FileRangeReads", func(t *testing.T) { verifyFileRangeReads(t, srcDir, mntDir) })
	t.Run("Symlinks", func(t *testing.T) { verifySymlinks(t, srcDir, mntDir) })
	t.Run("SymlinkResolution", func(t *testing.T) { verifySymlinkResolution(t, srcDir, mntDir) })
	t.Run("Metadata", func(t *testing.T) { verifyMetadata(t, srcDir, mntDir, compareMtimeNsec) })
	t.Run("Hardlinks", func(t *testing.T) { verifyHardlinks(t, srcDir, mntDir) })
	t.Run("SpecialFiles", func(t *testing.T) { verifySpecialFiles(t, srcDir, mntDir) })
	t.Run("Xattrs", func(t *testing.T) { verifyXattrs(t, srcDir, mntDir) })
}

func verifyPathSet(t *testing.T, srcDir, mntDir string) {
	t.Helper()
	assert.Equal(t, collectRelativePaths(t, srcDir), collectRelativePaths(t, mntDir))
}

func collectRelativePaths(t *testing.T, root string) []string {
	t.Helper()

	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		paths = append(paths, rel)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(paths)
	return paths
}

func verifyPathTypes(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil || rel == "." {
			return err
		}

		srcInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}

		mntInfo, err := os.Lstat(filepath.Join(mntDir, rel))
		require.NoError(t, err, "lstat mounted path: %s", rel)
		assert.Equal(t, srcInfo.Mode()&fs.ModeType, mntInfo.Mode()&fs.ModeType, "type mismatch: %s", rel)
		return nil
	})
	require.NoError(t, err)
}

func verifyFileContent(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeType != 0 {
			return nil
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		mntPath := filepath.Join(mntDir, rel)

		srcData, err := os.ReadFile(path)
		require.NoError(t, err, rel)

		mntData, err := os.ReadFile(mntPath)
		require.NoError(t, err, "read mounted file: %s", rel)
		assert.True(t, bytes.Equal(srcData, mntData), "content mismatch: %s", rel)
		return nil
	})
	require.NoError(t, err)
}

type readWindow struct {
	offset int64
	length int
}

func verifyFileRangeReads(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		mntPath := filepath.Join(mntDir, rel)

		srcData, err := os.ReadFile(path)
		require.NoError(t, err, rel)

		mntFile, err := os.Open(mntPath)
		require.NoError(t, err, "open mounted file: %s", rel)
		defer func() {
			require.NoError(t, mntFile.Close())
		}()

		if len(srcData) == 0 {
			buf := make([]byte, 1)
			n, readErr := mntFile.ReadAt(buf, 0)
			assert.Equal(t, 0, n, "empty file should not return data: %s", rel)
			assert.ErrorIs(t, readErr, io.EOF, "empty file should EOF on readat: %s", rel)
			return nil
		}

		for _, window := range interestingReadWindows(int64(len(srcData))) {
			want := expectedWindowBytes(srcData, window.offset, window.length)
			got := make([]byte, window.length)
			n, readErr := mntFile.ReadAt(got, window.offset)

			assert.Equal(t, len(want), n,
				"read length mismatch: %s off=%d len=%d", rel, window.offset, window.length)
			assert.True(t, bytes.Equal(want, got[:n]),
				"readat content mismatch: %s off=%d len=%d", rel, window.offset, window.length)
			if len(want) < window.length {
				assert.ErrorIs(t, readErr, io.EOF,
					"short read should report EOF: %s off=%d len=%d", rel, window.offset, window.length)
			} else {
				assert.NoError(t, readErr,
					"full read should succeed: %s off=%d len=%d", rel, window.offset, window.length)
			}
		}

		return nil
	})
	require.NoError(t, err)
}

func interestingReadWindows(size int64) []readWindow {
	base := []readWindow{
		{offset: 0, length: 1},
		{offset: 0, length: 17},
		{offset: 1, length: 33},
		{offset: 4095, length: 4},
		{offset: 4095, length: 257},
		{offset: 4095, length: 4097},
		{offset: 4096, length: 1},
		{offset: 4096, length: 257},
		{offset: 4097, length: 33},
		{offset: 8191, length: 4},
		{offset: 8191, length: 513},
		{offset: 8192, length: 17},
		{offset: 16383, length: 4},
		{offset: 16383, length: 1025},
		{offset: 16384, length: 33},
		{offset: size / 2, length: 257},
		{offset: size - 2, length: 4},
		{offset: size - 1, length: 2},
	}

	seen := make(map[readWindow]struct{})
	var windows []readWindow
	for _, window := range base {
		if window.offset < 0 || window.offset >= size || window.length <= 0 {
			continue
		}
		if _, ok := seen[window]; ok {
			continue
		}
		seen[window] = struct{}{}
		windows = append(windows, window)
	}

	return windows
}

func expectedWindowBytes(data []byte, offset int64, length int) []byte {
	start := int(offset)
	if start >= len(data) {
		return nil
	}
	end := start + length
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}

func verifySymlinks(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink == 0 {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		mntPath := filepath.Join(mntDir, rel)

		srcTarget, err := os.Readlink(path)
		require.NoError(t, err, rel)

		mntTarget, err := os.Readlink(mntPath)
		require.NoError(t, err, "readlink mounted: %s", rel)
		assert.Equal(t, srcTarget, mntTarget, "symlink target: %s", rel)
		return nil
	})
	require.NoError(t, err)
}

func verifySymlinkResolution(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink == 0 {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		mntPath := filepath.Join(mntDir, rel)

		srcInfo, srcErr := os.Stat(path)
		mntInfo, mntErr := os.Stat(mntPath)
		if srcErr != nil {
			assert.ErrorIs(t, srcErr, os.ErrNotExist, "unexpected symlink stat error: %s", rel)
			assert.ErrorIs(t, mntErr, os.ErrNotExist, "dangling symlink should stay dangling: %s", rel)
			return nil
		}

		require.NoError(t, mntErr, "stat mounted symlink target: %s", rel)
		assert.Equal(t, srcInfo.Mode()&fs.ModeType, mntInfo.Mode()&fs.ModeType,
			"resolved symlink type mismatch: %s", rel)

		if srcInfo.IsDir() {
			assert.Equal(t, readDirEntryNames(t, path), readDirEntryNames(t, mntPath),
				"resolved symlink directory entries mismatch: %s", rel)
			return nil
		}

		if srcInfo.Mode().IsRegular() {
			srcData, err := os.ReadFile(path)
			require.NoError(t, err, rel)

			mntData, err := os.ReadFile(mntPath)
			require.NoError(t, err, "read mounted symlink target: %s", rel)
			assert.True(t, bytes.Equal(srcData, mntData), "resolved symlink content mismatch: %s", rel)
		}

		return nil
	})
	require.NoError(t, err)
}

func readDirEntryNames(t *testing.T, path string) []string {
	t.Helper()

	entries, err := os.ReadDir(path)
	require.NoError(t, err, path)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func verifyMetadata(t *testing.T, srcDir, mntDir string, compareMtimeNsec bool) {
	t.Helper()

	var compactMtimeNsec *int64

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		mntPath := filepath.Join(mntDir, rel)

		srcInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}

		mntInfo, err := os.Lstat(mntPath)
		require.NoError(t, err, "lstat failed for mounted path: %s", rel)

		assert.Equal(t, srcInfo.Mode().Perm(), mntInfo.Mode().Perm(),
			"mode mismatch: %s (src=%o, mnt=%o)", rel, srcInfo.Mode().Perm(), mntInfo.Mode().Perm())

		srcSpecial := srcInfo.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		mntSpecial := mntInfo.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		assert.Equal(t, srcSpecial, mntSpecial, "special bits mismatch: %s", rel)

		srcStat := srcInfo.Sys().(*syscall.Stat_t)
		mntStat := mntInfo.Sys().(*syscall.Stat_t)
		assert.Equal(t, srcStat.Uid, mntStat.Uid, "uid mismatch: %s", rel)
		assert.Equal(t, srcStat.Gid, mntStat.Gid, "gid mismatch: %s", rel)
		assert.Equal(t, srcStat.Mtim.Sec, mntStat.Mtim.Sec, "mtime sec mismatch: %s", rel)
		if !compareMtimeNsec {
			// erofsfuse currently reports second-level timestamps for getattr, so the
			// compatibility comparison only verifies mtime seconds.
		} else if expectsExtendedInodeEncoding(srcInfo, srcStat) {
			assert.Equal(t, srcStat.Mtim.Nsec, mntStat.Mtim.Nsec, "mtime nsec mismatch: %s", rel)
		} else {
			mountedNsec := mntStat.Mtim.Nsec
			if compactMtimeNsec == nil {
				compactMtimeNsec = new(int64)
				*compactMtimeNsec = mountedNsec
			} else {
				assert.Equal(t, *compactMtimeNsec, mountedNsec,
					"compact inode fixed nsec mismatch: %s", rel)
			}
		}

		if !srcInfo.IsDir() {
			assert.Equal(t, srcStat.Nlink, mntStat.Nlink, "nlink mismatch: %s", rel)
		}

		if srcInfo.Mode().IsRegular() || srcInfo.Mode()&fs.ModeSymlink != 0 {
			assert.Equal(t, srcInfo.Size(), mntInfo.Size(), "size mismatch: %s", rel)
		}

		return nil
	})
	require.NoError(t, err)
}

func expectsExtendedInodeEncoding(info os.FileInfo, stat *syscall.Stat_t) bool {
	return info.Size() > int64(^uint32(0)) ||
		stat.Uid > uint32(^uint16(0)) ||
		stat.Gid > uint32(^uint16(0)) ||
		stat.Nlink > 1
}

func verifyHardlinks(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	groups := make(map[uint64][]string)
	singletons := make(map[string]struct{})
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}

		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return err
		}

		stat := info.Sys().(*syscall.Stat_t)
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		mntInfo, err := os.Stat(filepath.Join(mntDir, rel))
		require.NoError(t, err, rel)
		mntStat := mntInfo.Sys().(*syscall.Stat_t)
		assert.Equal(t, stat.Nlink, mntStat.Nlink, "hardlink count mismatch: %s", rel)

		if stat.Nlink < 2 {
			singletons[rel] = struct{}{}
			return nil
		}
		groups[stat.Ino] = append(groups[stat.Ino], rel)
		return nil
	})
	require.NoError(t, err)

	for _, rels := range groups {
		if len(rels) < 2 {
			continue
		}
		sort.Strings(rels)

		var mountedIno uint64
		for index, rel := range rels {
			mntInfo, err := os.Stat(filepath.Join(mntDir, rel))
			require.NoError(t, err, rel)

			mntStat := mntInfo.Sys().(*syscall.Stat_t)
			if index == 0 {
				mountedIno = mntStat.Ino
				continue
			}

			assert.Equal(t, mountedIno, mntStat.Ino, "hardlink inode mismatch: %v", rels)
		}
	}

	seenMountedInodes := make(map[uint64]string)
	for rel := range singletons {
		mntInfo, err := os.Stat(filepath.Join(mntDir, rel))
		require.NoError(t, err, rel)

		mntStat := mntInfo.Sys().(*syscall.Stat_t)
		if prev, ok := seenMountedInodes[mntStat.Ino]; ok {
			assert.Failf(t, "unexpected hardlink alias",
				"mounted singleton files %s and %s unexpectedly share inode %d", prev, rel, mntStat.Ino)
			continue
		}
		seenMountedInodes[mntStat.Ino] = rel
	}
}

func verifySpecialFiles(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}

		srcInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}

		modeType := srcInfo.Mode() & fs.ModeType
		if modeType == 0 {
			return nil
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		mntInfo, err := os.Lstat(filepath.Join(mntDir, rel))
		require.NoError(t, err, rel)
		assert.Equal(t, modeType, mntInfo.Mode()&fs.ModeType, "special file type mismatch: %s", rel)

		if modeType&fs.ModeDevice != 0 {
			srcStat := srcInfo.Sys().(*syscall.Stat_t)
			mntStat := mntInfo.Sys().(*syscall.Stat_t)
			assert.Equal(t, srcStat.Rdev, mntStat.Rdev, "device mismatch: %s", rel)
		}

		return nil
	})
	require.NoError(t, err)
}

func verifyXattrs(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	xattrDir := filepath.Join(srcDir, "xattrs")
	err := filepath.WalkDir(xattrDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		mntPath := filepath.Join(mntDir, rel)
		srcNames, err := xattr.List(path)
		if err != nil {
			return err
		}

		mntNames, err := xattr.List(mntPath)
		require.NoError(t, err, "listxattr: %s", rel)

		sort.Strings(srcNames)
		sort.Strings(mntNames)
		assert.Equal(t, srcNames, mntNames, "xattr names mismatch: %s", rel)
		for _, name := range srcNames {
			srcVal, err := xattr.Get(path, name)
			require.NoError(t, err)

			mntVal, err := xattr.Get(mntPath, name)
			require.NoError(t, err, "getxattr %s on %s", name, rel)
			assert.True(t, bytes.Equal(srcVal, mntVal),
				"xattr value mismatch: %s key=%s", rel, name)
		}
		return nil
	})
	require.NoError(t, err)
}

func verifyWhiteoutResults(t *testing.T, mountpoint string) {
	t.Helper()
	requireNotExist(t, filepath.Join(mountpoint, "merge", "remove.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "dir", "base.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "opq", "old.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "opq", "subdir"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", ".wh.remove.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "dir", ".wh.base.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "opq", ".wh..wh..opq"))
}

func printMergeDebugPaths(t *testing.T, layer1Dir, layer2Dir, layer3Dir, mountpoint string) {
	t.Helper()
	message := fmt.Sprintf(
		"merge test paths:\n  layer1=%s\n  layer2=%s\n  layer3=%s\n  mountpoint=%s\n",
		layer1Dir,
		layer2Dir,
		layer3Dir,
		mountpoint,
	)
	t.Logf("%s", message)
	_, _ = fmt.Fprint(os.Stderr, message)
}

func logLeptonCheckOutput(t *testing.T, leptonBin string, args ...string) {
	t.Helper()

	cmdArgs := append([]string{"check"}, args...)
	out, err := exec.Command(leptonBin, cmdArgs...).CombinedOutput()
	require.NoError(t, err, "lepton check failed: %s", string(out))
	t.Logf("lepton %s output:\n%s", strings.Join(cmdArgs, " "), string(out))
}

func pauseMergeDebugIfRequested(t *testing.T, mountpoint string) {
	t.Helper()
	pauseSecs := texture.GetEnvAsInt("LEPTONFS_MERGE_PAUSE_SECS", 0)
	if pauseSecs <= 0 {
		return
	}

	message := fmt.Sprintf(
		"pausing merge test for %d seconds before cleanup; inspect mountpoint: %s\n",
		pauseSecs,
		mountpoint,
	)
	t.Logf("%s", message)
	_, _ = fmt.Fprint(os.Stderr, message)
	time.Sleep(time.Duration(pauseSecs) * time.Second)
}

func requireNotExist(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	require.True(t, errors.Is(err, os.ErrNotExist), "expected path to be absent: %s", path)
}

func verifyBlobCacheArtifacts(t *testing.T, cacheDir string, blobs ...string) {
	t.Helper()

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)

	var dataCount int
	var groupmapCount int
	var blobmetaCount int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".blob.data"):
			dataCount++
		case strings.HasSuffix(name, ".groupmap"):
			groupmapCount++
		case strings.HasSuffix(name, ".blob.meta"):
			blobmetaCount++
		}
	}

	blobCount := len(blobs)
	assert.Equal(t, blobCount, dataCount, "unexpected cached blob.data count")
	assert.Equal(t, blobCount, groupmapCount, "unexpected cached groupmap count")
	assert.Equal(t, blobCount, blobmetaCount, "unexpected cached blobmeta count")

	for _, blob := range blobs {
		prefix := fullBlobDigest(t, blob)
		require.FileExists(t, filepath.Join(cacheDir, prefix+".blob.data"))
		require.FileExists(t, filepath.Join(cacheDir, prefix+".blob.meta"))
		require.FileExists(t, filepath.Join(cacheDir, prefix+".groupmap"))
	}
}
