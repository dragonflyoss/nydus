package integration

import (
	"bytes"
	"errors"
	"fmt"
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

func TestBlobMountE2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	bootstrapPath := filepath.Join(tmpDir, "test.bootstrap")
	blobDir := filepath.Join(tmpDir, "blobs")
	mntDir := filepath.Join(tmpDir, "mnt")

	t.Log("Generating corpus...")
	texture.MakeStandardCorpus(t, corpusDir)

	t.Log("Building blob and mounting it directly...")
	leptonBin := mustLookupExecutable(t, "lepton")
	blobPath := buildLeptonFSImageToDir(t, leptonBin, bootstrapPath, blobDir, corpusDir, 4096)
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

	unmount := mountLeptonBootstrap(t, leptonBin, mergedBootstrap, blobDir, mountpoint)
	defer unmount()
	printMergeDebugPaths(t, layer1Dir, layer2Dir, layer3Dir, mountpoint)

	verifyMountedTree(t, expectedDir, mountpoint)
	verifyWhiteoutResults(t, mountpoint)
	pauseMergeDebugIfRequested(t, mountpoint)
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
	layer2.CreateDir(t, "xattrs/merged_dir")
	layer2.SetXattr(t, "xattrs/merged_dir", "user.dir.merged", []byte("layer2-dir"))
	layer2.CreateSymlink(t, "symlinks/merged_link", "../files/tiny_2b")
	layer2.CreateFIFO(t, "special/upper_fifo")
	layer2.CreateFile(t, "upperhard/original", []byte("upper shared"))
	layer2.CreateHardlink(t, "upperhard/link1", "upperhard/original")

	layer3 := texture.NewCorpus(t, layer3Dir)
	layer3.CreateFile(t, "files/tiny_2b", []byte("ok"))
	layer3.CreateFile(t, "merge/lower.txt", []byte("lower-v3"))
	layer3.CreateFile(t, "merge/dir/.wh.base.txt", nil)
	layer3.CreateFile(t, "merge/dir/top.txt", []byte("top-from-layer3"))
	layer3.CreateFile(t, "merge/opq/.wh..wh..opq", nil)
	layer3.CreateFile(t, "merge/opq/new.txt", []byte("new-from-layer3"))

	cloneTreePreservingLinks(t, layer1Dir, expectedDir)
	expected := &texture.Corpus{Dir: expectedDir}
	expected.CreateFile(t, "xattrs/merged_upper", []byte("merged upper xattr\n"))
	expected.SetXattr(t, "xattrs/merged_upper", "user.merged", []byte("layer2"))
	expected.CreateDir(t, "xattrs/merged_dir")
	expected.SetXattr(t, "xattrs/merged_dir", "user.dir.merged", []byte("layer2-dir"))
	expected.CreateSymlink(t, "symlinks/merged_link", "../files/tiny_2b")
	expected.CreateFIFO(t, "special/upper_fifo")
	expected.CreateFile(t, "upperhard/original", []byte("upper shared"))
	expected.CreateHardlink(t, "upperhard/link1", "upperhard/original")
	expected.CreateFile(t, "files/tiny_2b", []byte("ok"))
	expected.CreateFile(t, "merge/lower.txt", []byte("lower-v3"))
	expected.CreateFile(t, "merge/middle.txt", []byte("middle-from-layer2"))
	expected.CreateFile(t, "merge/dir/mid.txt", []byte("mid-from-layer2"))
	expected.CreateFile(t, "merge/dir/top.txt", []byte("top-from-layer3"))

	removeExpectedPath(t, expectedDir, "merge/remove.txt")
	removeExpectedPath(t, expectedDir, "merge/dir/base.txt")
	removeExpectedPath(t, expectedDir, "merge/opq")
	expected.CreateFile(t, "merge/opq/new.txt", []byte("new-from-layer3"))
}

func cloneTreePreservingLinks(t *testing.T, srcDir, dstDir string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(dstDir))
	require.NoError(t, os.MkdirAll(dstDir, 0755))
	copySource := srcDir + string(os.PathSeparator) + "."
	out, err := exec.Command("cp", "-a", copySource, dstDir).CombinedOutput()
	require.NoError(t, err, "cp -a failed: %s", string(out))
}

func addMergeBaseEntries(t *testing.T, corpus *texture.Corpus) {
	t.Helper()

	corpus.CreateFile(t, "merge/lower.txt", []byte("lower-v1"))
	corpus.CreateFile(t, "merge/remove.txt", []byte("remove-me"))
	corpus.CreateFile(t, "merge/shared/keep.txt", []byte("shared-from-layer1"))
	corpus.CreateFile(t, "merge/dir/base.txt", []byte("base-from-layer1"))
	corpus.CreateFile(t, "merge/opq/old.txt", []byte("old-from-layer1"))
	corpus.CreateFile(t, "merge/opq/subdir/old_nested.txt", []byte("nested-old-from-layer1"))
}

func removeExpectedPath(t *testing.T, root, rel string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(filepath.Join(root, rel)))
}

func verifyMountedTree(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	t.Run("PathSet", func(t *testing.T) { verifyPathSet(t, srcDir, mntDir) })
	t.Run("PathTypes", func(t *testing.T) { verifyPathTypes(t, srcDir, mntDir) })
	t.Run("FileContent", func(t *testing.T) { verifyFileContent(t, srcDir, mntDir) })
	t.Run("Symlinks", func(t *testing.T) { verifySymlinks(t, srcDir, mntDir) })
	t.Run("Metadata", func(t *testing.T) { verifyMetadata(t, srcDir, mntDir) })
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

func verifyMetadata(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil || rel == "." {
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

		if srcInfo.Mode().IsRegular() {
			assert.Equal(t, srcInfo.Size(), mntInfo.Size(), "size mismatch: %s", rel)
		}

		return nil
	})
	require.NoError(t, err)
}

func verifyHardlinks(t *testing.T, srcDir, mntDir string) {
	t.Helper()

	groups := make(map[uint64][]string)
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}

		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return err
		}

		stat := info.Sys().(*syscall.Stat_t)
		if stat.Nlink < 2 {
			return nil
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
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
		if err != nil || len(srcNames) == 0 {
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
