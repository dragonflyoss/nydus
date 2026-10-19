package e2e

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
)

// TestMergedMount builds three overlay layers with whiteouts, an opaque
// directory and type changes, merges them and diffs the mount, without and
// with a chunk cache, against the expected merged tree.
func TestMergedMount(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")

	workDir := t.TempDir()
	layer1Dir := filepath.Join(workDir, "layer1")
	layer2Dir := filepath.Join(workDir, "layer2")
	layer3Dir := filepath.Join(workDir, "layer3")
	expectedDir := filepath.Join(workDir, "expected")
	mountpoint := filepath.Join(workDir, "mnt")
	prepareMergeLayers(t, layer1Dir, layer2Dir, layer3Dir, expectedDir)

	// Build one image per layer and merge them.
	blobDir := filepath.Join(workDir, "blobs")
	layer1Bootstrap := filepath.Join(workDir, "layer1.bootstrap")
	layer2Bootstrap := filepath.Join(workDir, "layer2.bootstrap")
	layer3Bootstrap := filepath.Join(workDir, "layer3.bootstrap")
	mergedBootstrap := filepath.Join(workDir, "merged.bootstrap")
	cacheDir := filepath.Join(workDir, "cache")
	layer1Blob := util.BuildImage(t, nydusBin, layer1Bootstrap, blobDir, layer1Dir, 4096)
	layer2Blob := util.BuildImage(t, nydusBin, layer2Bootstrap, blobDir, layer2Dir, 4096)
	layer3Blob := util.BuildImage(t, nydusBin, layer3Bootstrap, blobDir, layer3Dir, 4096)
	util.CheckImage(t, nydusBin, "--bootstrap", layer1Bootstrap, "--blob-dir", blobDir)
	util.MergeBootstrap(t, nydusBin, mergedBootstrap, layer1Blob, layer2Blob, layer3Blob)
	util.CheckImage(t, nydusBin, "--bootstrap", mergedBootstrap, "--blob-dir", blobDir)

	func() {
		unmount := util.MountNydusBootstrap(t, nydusBin, mergedBootstrap, blobDir, "", mountpoint)
		defer unmount()
		util.CheckDirectoryEqual(t, expectedDir, mountpoint, true)
		verifyWhiteoutsApplied(t, mountpoint)
	}()

	func() {
		unmount := util.MountNydusBootstrap(t, nydusBin, mergedBootstrap, blobDir, cacheDir, mountpoint)
		defer unmount()
		util.CheckDirectoryEqual(t, expectedDir, mountpoint, true)
		verifyWhiteoutsApplied(t, mountpoint)
		verifyChunkCacheFiles(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)
	}()
}

// prepareMergeLayers writes the three overlay layers of the merge tests and
// the expected result of merging them: the standard corpus plus merge entries
// as the base, a middle layer with whiteouts, xattr and symlink overrides, and
// a top layer with an opaque directory and type changes.
func prepareMergeLayers(t *testing.T, layer1Dir, layer2Dir, layer3Dir, expectedDir string) {
	t.Helper()
	base := corpus.MakeStandardCorpus(t, layer1Dir)
	base.CreateFile(t, "merge/lower.txt", []byte("lower-v1"))
	base.CreateFile(t, "merge/remove.txt", []byte("remove-me"))
	base.CreateFile(t, "merge/shared/keep.txt", []byte("shared-from-layer1"))
	base.CreateFile(t, "merge/dir/base.txt", []byte("base-from-layer1"))
	base.CreateFile(t, "merge/opq/old.txt", []byte("old-from-layer1"))
	base.CreateFile(t, "merge/opq/subdir/old_nested.txt", []byte("nested-old-from-layer1"))
	base.CreateFile(t, "merge/type_file_to_link", []byte("layer1-regular"))
	base.CreateSymlink(t, "merge/type_link_to_file", "../files/tiny_2b")
	base.CreateFile(t, "xattrs/merged_override", []byte("merged override from layer1\n"))
	base.SetXattr(t, "xattrs/merged_override", "user.layer", []byte("layer1"))

	layer2 := corpus.NewCorpus(t, layer2Dir)
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

	layer3 := corpus.NewCorpus(t, layer3Dir)
	layer3.CreateFile(t, "files/tiny_2b", []byte("ok"))
	layer3.CreateFile(t, "merge/lower.txt", []byte("lower-v3"))
	layer3.CreateFile(t, "merge/type_link_to_file", []byte("layer3-file-wins"))
	layer3.CreateFile(t, "merge/dir/.wh.base.txt", nil)
	layer3.CreateFile(t, "merge/dir/top.txt", []byte("top-from-layer3"))
	layer3.CreateFile(t, "merge/opq/.wh..wh..opq", nil)
	layer3.CreateFile(t, "merge/opq/new.txt", []byte("new-from-layer3"))

	// Start the expected tree from a hardlink-preserving copy of the base and
	// overlay the upper entries on it.
	assert.NoError(t, os.RemoveAll(expectedDir))
	assert.NoError(t, os.MkdirAll(expectedDir, 0o755))
	out, err := exec.Command("cp", "-a", layer1Dir+string(os.PathSeparator)+".", expectedDir).CombinedOutput()
	assert.NoError(t, err, "cp -a failed: %s", out)
	for _, upper := range []struct {
		layerDir string
		rel      string
	}{
		{layer2Dir, "xattrs/merged_upper"},
		{layer2Dir, "xattrs/merged_override"},
		{layer2Dir, "xattrs/merged_dir"},
		{layer2Dir, "symlinks/merged_link"},
		{layer2Dir, "special/upper_fifo"},
		{layer2Dir, "upperhard"},
		{layer2Dir, "merge/type_file_to_link"},
		{layer3Dir, "merge/type_link_to_file"},
		{layer3Dir, "files/tiny_2b"},
		{layer3Dir, "merge/lower.txt"},
		{layer2Dir, "merge/middle.txt"},
		{layer2Dir, "merge/dir/mid.txt"},
		{layer3Dir, "merge/dir/top.txt"},
	} {
		copyPathPreservingMetadata(t, upper.layerDir, expectedDir, upper.rel)
	}

	// Apply the whiteouts and the opaque directory, then the directory
	// metadata of the upper layers.
	assert.NoError(t, os.RemoveAll(filepath.Join(expectedDir, "merge/remove.txt")))
	assert.NoError(t, os.RemoveAll(filepath.Join(expectedDir, "merge/dir/base.txt")))
	assert.NoError(t, os.RemoveAll(filepath.Join(expectedDir, "merge/opq")))
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/opq/new.txt")
	overlayDirectoryMetadata(t, layer2Dir, expectedDir)
	overlayDirectoryMetadata(t, layer3Dir, expectedDir)
}

// copyPathPreservingMetadata replaces rel under dstRoot with a `cp -a` copy
// of rel under srcRoot.
func copyPathPreservingMetadata(t *testing.T, srcRoot, dstRoot, rel string) {
	t.Helper()
	srcPath := filepath.Join(srcRoot, rel)
	dstPath := filepath.Join(dstRoot, rel)
	assert.NoError(t, os.MkdirAll(filepath.Dir(dstPath), 0o755))
	assert.NoError(t, os.RemoveAll(dstPath))
	out, err := exec.Command("cp", "-a", srcPath, dstPath).CombinedOutput()
	assert.NoError(t, err, "cp -a failed: %s", out)
}

// overlayDirectoryMetadata copies the metadata of every directory under
// srcRoot onto its counterpart under dstRoot, as an overlay merge takes
// directory metadata from the upper layer.
func overlayDirectoryMetadata(t *testing.T, srcRoot, dstRoot string) {
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
	assert.NoError(t, err)
}

// copyDirectoryMetadata copies mode, owner, timestamps and xattrs from the
// directory srcPath to the directory dstPath, and does nothing when either
// is not a directory.
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

// syncXattrs makes the xattrs of dstPath equal to those of srcPath, setting
// every source xattr and removing the ones only the destination carries.
func syncXattrs(srcPath, dstPath string) error {
	srcNames, err := xattr.List(srcPath)
	if err != nil {
		return err
	}
	dstNames, err := xattr.List(dstPath)
	if err != nil {
		return err
	}

	for _, name := range srcNames {
		value, err := xattr.Get(srcPath, name)
		if err != nil {
			return err
		}
		if err := xattr.Set(dstPath, name, value); err != nil {
			return err
		}
	}

	for _, name := range dstNames {
		if slices.Contains(srcNames, name) {
			continue
		}
		if err := xattr.Remove(dstPath, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// verifyWhiteoutsApplied checks the whiteouts of the merged layers removed
// their targets and that no whiteout marker leaked into the mount.
func verifyWhiteoutsApplied(t *testing.T, mountpoint string) {
	t.Helper()
	for _, rel := range []string{
		"merge/remove.txt",
		"merge/dir/base.txt",
		"merge/opq/old.txt",
		"merge/opq/subdir",
		"merge/.wh.remove.txt",
		"merge/dir/.wh.base.txt",
		"merge/opq/.wh..wh..opq",
	} {
		path := filepath.Join(mountpoint, rel)
		_, err := os.Lstat(path)
		assert.ErrorIs(t, err, os.ErrNotExist, "expected path to be absent: %s", path)
	}
}
