package integration

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/dragonflyoss/lepton/tests/integration/texture"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyLeptonFS builds an LeptonFS image from a generated corpus, mounts it,
// and verifies that all metadata and content are preserved end-to-end.
func TestVerifyLeptonFS(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	imagePath := filepath.Join(tmpDir, "test.image")
	blobdev := filepath.Join(tmpDir, "test.blob")
	mntDir := filepath.Join(tmpDir, "mnt")

	// Generate corpus for testing.
	t.Log("Generating corpus...")
	texture.MakeStandardCorpus(t, corpusDir)
	_ = os.Remove(imagePath)
	_ = os.Remove(blobdev)

	// Build LeptonFS image and mount it.
	t.Log("Building LeptonFS image and mounting...")
	leptonBin := mustLookupExecutable(t, "lepton")
	buildLeptonFSImage(t, leptonBin, imagePath, blobdev, corpusDir, 4096)
	unmount := mountLepton(t, leptonBin, imagePath, blobdev, mntDir)
	defer unmount()

	t.Run("FileContent", func(t *testing.T) { verifyFileContent(t, corpusDir, mntDir) })
	t.Run("Symlinks", func(t *testing.T) { verifySymlinks(t, corpusDir, mntDir) })
	t.Run("Directories", func(t *testing.T) { verifyDirectories(t, corpusDir, mntDir) })
	t.Run("Metadata", func(t *testing.T) { verifyMetadata(t, corpusDir, mntDir) })
	t.Run("Hardlinks", func(t *testing.T) { verifyHardlinks(t, mntDir) })
	t.Run("Xattrs", func(t *testing.T) { verifyXattrs(t, corpusDir, mntDir) })
}

// verifyFileContent checks that every regular file in srcDir has the same
// byte content when read from the mounted filesystem.
func verifyFileContent(t *testing.T, srcDir, mntDir string) {
	_ = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		// Skip non-regular files (devices, FIFOs).
		info, err := d.Info()
		if err != nil || info.Mode()&fs.ModeType != 0 {
			return nil
		}

		rel, _ := filepath.Rel(srcDir, path)
		mntPath := filepath.Join(mntDir, rel)

		srcData, err := os.ReadFile(path)
		require.NoError(t, err, rel)

		mntData, err := os.ReadFile(mntPath)
		require.NoError(t, err, "read mounted file: %s", rel)
		assert.True(t, bytes.Equal(srcData, mntData), "content mismatch: %s", rel)
		return nil
	})
}

// verifySymlinks checks that every symbolic link in srcDir resolves to the
// same target on the mounted filesystem.
func verifySymlinks(t *testing.T, srcDir, mntDir string) {
	_ = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		rel, _ := filepath.Rel(srcDir, path)
		mntPath := filepath.Join(mntDir, rel)

		srcTarget, err := os.Readlink(path)
		require.NoError(t, err, rel)

		mntTarget, err := os.Readlink(mntPath)
		require.NoError(t, err, "readlink mounted: %s", rel)
		assert.Equal(t, srcTarget, mntTarget, "symlink target: %s", rel)
		return nil
	})
}

// verifyDirectories checks that every directory in srcDir exists as a
// directory on the mounted filesystem.
func verifyDirectories(t *testing.T, srcDir, mntDir string) {
	_ = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(srcDir, path)
		if rel == "." {
			return nil
		}

		mntPath := filepath.Join(mntDir, rel)
		info, err := os.Stat(mntPath)
		require.NoError(t, err, "directory missing: %s", rel)
		assert.True(t, info.IsDir(), "not a directory: %s", rel)
		return nil
	})
}

// verifyMetadata checks that permission bits, special bits, ownership, and
// regular-file sizes match between srcDir and the mounted filesystem.
func verifyMetadata(t *testing.T, srcDir, mntDir string) {
	_ = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(srcDir, path)
		if rel == "." {
			return nil
		}
		mntPath := filepath.Join(mntDir, rel)

		srcInfo, err := os.Lstat(path)
		if err != nil {
			return nil
		}

		mntInfo, err := os.Lstat(mntPath)
		if err != nil {
			t.Errorf("lstat failed for mounted path: %s", rel)
			return nil
		}

		// Permission bits.
		assert.Equal(t, srcInfo.Mode().Perm(), mntInfo.Mode().Perm(),
			"mode mismatch: %s (src=%o, mnt=%o)", rel, srcInfo.Mode().Perm(), mntInfo.Mode().Perm())

		// Special bits (setuid, setgid, sticky).
		srcSpecial := srcInfo.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		mntSpecial := mntInfo.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		assert.Equal(t, srcSpecial, mntSpecial, "special bits mismatch: %s", rel)

		// Ownership.
		srcStat := srcInfo.Sys().(*syscall.Stat_t)
		mntStat := mntInfo.Sys().(*syscall.Stat_t)
		assert.Equal(t, srcStat.Uid, mntStat.Uid, "uid mismatch: %s", rel)
		assert.Equal(t, srcStat.Gid, mntStat.Gid, "gid mismatch: %s", rel)

		// Size for regular files.
		if srcInfo.Mode().IsRegular() {
			assert.Equal(t, srcInfo.Size(), mntInfo.Size(), "size mismatch: %s", rel)
		}

		return nil
	})
}

// verifyHardlinks checks that all hard-link entries share the same inode as
// the original file under hardlinks/.
func verifyHardlinks(t *testing.T, mntDir string) {
	origPath := filepath.Join(mntDir, "hardlinks/original")
	origInfo, err := os.Stat(origPath)
	require.NoError(t, err)
	origIno := origInfo.Sys().(*syscall.Stat_t).Ino

	for _, link := range []string{"hardlinks/link1", "hardlinks/link2", "hardlinks/subdir/link3"} {
		linkPath := filepath.Join(mntDir, link)
		linkInfo, err := os.Stat(linkPath)
		require.NoError(t, err, link)

		linkIno := linkInfo.Sys().(*syscall.Stat_t).Ino
		assert.Equal(t, origIno, linkIno, "hardlink inode mismatch: %s", link)
	}
}

// verifyXattrs checks that extended-attribute names and values under the
// xattrs/ subtree match between srcDir and the mounted filesystem.
func verifyXattrs(t *testing.T, srcDir, mntDir string) {
	xattrDir := filepath.Join(srcDir, "xattrs")
	_ = filepath.WalkDir(xattrDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(srcDir, path)
		mntPath := filepath.Join(mntDir, rel)
		srcNames, err := xattr.List(path)
		if err != nil || len(srcNames) == 0 {
			return nil
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
}

// TestXfstests runs the xfstests read-only suite against a `lepton mount`.
func TestXfstests(t *testing.T) {
	if os.Getenv("LEPTONFS_RUN_XFSTESTS") != "1" {
		t.Skip("set LEPTONFS_RUN_XFSTESTS=1 to enable")
	}

	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}

	corpusDir := filepath.Join("/tmp", "corpus.xfstests")
	xfstestsDir := filepath.Join("/tmp", "xfstests-dev")
	imagePath := filepath.Join("/tmp", "test.image.xfstests")
	blobdev := filepath.Join("/tmp", "test.blob.xfstests")
	mntDir := filepath.Join("/tmp", "mnt.xfstests")

	// Ensure xfstests is built (setup_xfstests.sh handles deps).
	setupXfstests(t, xfstestsDir)
	leptonBin := mustLookupExecutable(t, "lepton")

	// Generate corpus for testing.
	t.Log("Generating corpus...")
	corpus := texture.MakeStandardCorpus(t, corpusDir)
	_ = os.Remove(imagePath)
	_ = os.Remove(blobdev)

	// Build LeptonFS image and mount it.
	t.Log("Building LeptonFS image...")
	buildLeptonFSImage(t, leptonBin, imagePath, blobdev, corpus.Dir, 4096)

	// Install the FUSE mount helper used by xfstests.
	installMountHelper(t, leptonBin, imagePath, blobdev)

	// Write xfstests local.config.
	require.NoError(t, os.MkdirAll(mntDir, 0755))
	config := fmt.Sprintf(
		"export TEST_DEV=testleptonfs\nexport TEST_DIR=%s\nexport FSTYP=fuse\nexport FUSE_SUBTYP=.testleptonfs\n",
		mntDir,
	)
	require.NoError(t, os.WriteFile(filepath.Join(xfstestsDir, "local.config"), []byte(config), 0644))

	// Locate the xfstests exclude file used to skip unsupported cases.
	excludeFile, err := filepath.Abs(filepath.Join("..", "scripts", "xfstests_leptonfs.exclude"))
	require.NoError(t, err)
	require.FileExists(t, excludeFile)

	// Run xfstests.
	t.Log("Running xfstests (this may take several minutes)...")
	cmd := exec.Command("./check", "-fuse", "-E", excludeFile)
	cmd.Dir = xfstestsDir
	cmd.Env = append(os.Environ(), "FSTYP=fuse")
	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Log(output)
	require.NoError(t, err, "xfstests exited with error")

	// Parse results.
	if strings.Contains(output, "Passed all") {
		return
	}

	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "Failures:") || strings.Contains(line, "Failed") {
			require.Fail(t, "xfstests reported failures (see log above)")
		}
	}
}

// installMountHelper writes a helper script to /usr/local/bin/testleptonfs that xfstests will invoke to
// mount the LeptonFS image. The script ensures that the mount is ready before returning, and logs
// output for debugging.
func installMountHelper(t *testing.T, leptonBin, imagePath, blobdev string) {
	script := fmt.Sprintf(`#!/bin/bash
# xfstests may invoke this as either:
#   testleptonfs <mountpoint>
# or:
#   testleptonfs <device> <mountpoint>
if [ "$#" -ge 2 ]; then
    DEVICE="$1"
    MOUNTPOINT="$2"
else
    DEVICE="testleptonfs"
    MOUNTPOINT="$1"
fi
[ -z "$MOUNTPOINT" ] && MOUNTPOINT="/tmp/leptonfs_mount"
ulimit -n 1048576
pkill -f "lepton mount.*${MOUNTPOINT}" 2>/dev/null || true
fusermount -u "${MOUNTPOINT}" 2>/dev/null || true
sleep 0.5
%s mount %s "${MOUNTPOINT}" --blobdev %s --fsname "${DEVICE}" 1>>/tmp/leptonfs.log 2>&1 &
for i in $(seq 1 20); do
    mountpoint -q "${MOUNTPOINT}" 2>/dev/null && exit 0
    sleep 0.5
done
echo "ERROR: lepton mount failed to mount within 10 seconds" >&2
exit 1
`, leptonBin, imagePath, blobdev)

	const helperPath = "/usr/local/bin/testleptonfs"
	require.NoError(t, os.WriteFile(helperPath, []byte(script), 0755))
}
