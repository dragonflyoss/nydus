// Package integration contains end-to-end tests for the lepton binary.
//
// The tests in this file build an EROFS image from a generated corpus, mount
// it through `lepton mount`, and then verify file content, metadata,
// symlinks, hard links, and extended attributes. A separate test optionally
// runs the xfstests read-only suite against the same mount.
//
// Both tests require root privileges and the `lepton` binary to be available
// either on PATH or under ../../target/{release,debug}/.
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
	"time"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/erofs/erofs-utils-rust/tests/integration/texture"
)

// Binary discovery.

// findBinary locates an executable by name, preferring PATH and falling back
// to ../../target/{release,debug}/<name> relative to this package.
func findBinary(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	for _, profile := range []string{"release", "debug"} {
		p := filepath.Join(root, "target", profile, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// requireBinary returns the resolved path of an executable or fails the test
// if it cannot be found.
func requireBinary(t *testing.T, name string) string {
	t.Helper()
	p := findBinary(name)
	if p == "" {
		t.Fatalf("%s not found on PATH or in target/{release,debug}/", name)
	}
	return p
}

// FUSE mount helpers.

// mountLepton runs `lepton mount` in the background and returns a cleanup
// function that unmounts the filesystem and reaps the child process.
func mountLepton(t *testing.T, leptonBin, img, blobdev, mnt string) (cleanup func()) {
	t.Helper()
	require.NoError(t, os.MkdirAll(mnt, 0755))

	args := []string{"mount", img, mnt}
	if blobdev != "" {
		args = append(args, "--blobdev", blobdev)
	}

	cmd := exec.Command(leptonBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "lepton mount start")

	// Wait for the mountpoint to become ready (up to ~10s).
	mounted := false
	for range 40 {
		if isMountpoint(mnt) {
			mounted = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	require.True(t, mounted, "lepton mount failed to mount within 10s")

	return func() {
		_ = exec.Command("fusermount", "-u", mnt).Run()
		// Send SIGTERM and don't block indefinitely while waiting.
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
			}
		}
	}
}

// isMountpoint reports whether path is currently a mountpoint.
func isMountpoint(path string) bool {
	return exec.Command("mountpoint", "-q", path).Run() == nil
}

// Image build helpers.

// buildEROFSImage invokes `lepton build` to create an EROFS image and its
// associated blob device file.
func buildEROFSImage(t *testing.T, leptonBin, img, blobdev, srcDir string) {
	t.Helper()
	args := []string{"build", img, "--blobdev", blobdev, "--chunksize", "4096", srcDir}
	out, err := exec.Command(leptonBin, args...).CombinedOutput()
	require.NoError(t, err, "lepton build failed: %s", string(out))
	t.Logf("lepton build output: %s", string(out))
}

// TestVerifyEROFS builds an EROFS image from a generated corpus, mounts it,
// and verifies that all metadata and content are preserved end-to-end.
func TestVerifyEROFS(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	leptonBin := requireBinary(t, "lepton")

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	img := filepath.Join(tmpDir, "test.erofs")
	blob := filepath.Join(tmpDir, "test.blob")
	mnt := filepath.Join(tmpDir, "mnt")

	// Generate the standard test corpus and build an EROFS image from it.
	texture.MakeStandardCorpus(t, corpusDir)
	buildEROFSImage(t, leptonBin, img, blob, corpusDir)

	// Mount the image and run verification sub-tests against it.
	unmount := mountLepton(t, leptonBin, img, blob, mnt)
	defer unmount()

	t.Run("FileContent", func(t *testing.T) { verifyFileContent(t, corpusDir, mnt) })
	t.Run("Symlinks", func(t *testing.T) { verifySymlinks(t, corpusDir, mnt) })
	t.Run("Directories", func(t *testing.T) { verifyDirectories(t, corpusDir, mnt) })
	t.Run("Metadata", func(t *testing.T) { verifyMetadata(t, corpusDir, mnt) })
	t.Run("Hardlinks", func(t *testing.T) { verifyHardlinks(t, mnt) })
	t.Run("Xattrs", func(t *testing.T) { verifyXattrs(t, corpusDir, mnt) })
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

		// uid / gid.
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
	if _, err := os.Stat(xattrDir); os.IsNotExist(err) {
		t.Skip("no xattrs directory in corpus")
	}

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
// The test is gated by EROFS_RUN_XFSTESTS=1 because it is slow and requires
// xfstests to be set up on the host.
func TestXfstests(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("EROFS_RUN_XFSTESTS") == "" {
		t.Skip("set EROFS_RUN_XFSTESTS=1 to enable (slow)")
	}

	leptonBin := requireBinary(t, "lepton")

	const (
		xfstestsDir = "/tmp/xfstests-dev"
		img         = "/tmp/test_erofs.img"
		blob        = "/tmp/test_erofs.blob"
		mntDir      = "/tmp/erofs_mount"
		corpusDir   = "/tmp/erofs_test_corpus"
	)

	// Locate the xfstests exclude file used to skip unsupported cases.
	excludeFile, err := filepath.Abs(filepath.Join("..", "scripts", "xfstests_erofs.exclude"))
	require.NoError(t, err)
	require.FileExists(t, excludeFile)

	// Step 1: ensure xfstests is built (setup_xfstests.sh handles deps).
	if _, err := os.Stat(filepath.Join(xfstestsDir, "check")); os.IsNotExist(err) {
		setupScript, err2 := filepath.Abs(filepath.Join("..", "scripts", "setup_xfstests.sh"))
		require.NoError(t, err2)
		require.FileExists(t, setupScript)
		out, err2 := exec.Command("bash", setupScript).CombinedOutput()
		require.NoError(t, err2, "setup_xfstests.sh failed:\n%s", string(out))
	}

	// Step 2: generate corpus and build the image.
	corpus := texture.MakeStandardCorpus(t, corpusDir)
	_ = os.Remove(img)
	_ = os.Remove(blob)
	buildEROFSImage(t, leptonBin, img, blob, corpus.Dir)

	// Step 3: install the FUSE mount helper used by xfstests.
	installMountHelper(t, leptonBin, img, blob)

	// Step 4: write xfstests local.config.
	require.NoError(t, os.MkdirAll(mntDir, 0755))
	config := fmt.Sprintf(
		"export TEST_DEV=testerofs\nexport TEST_DIR=%s\nexport FSTYP=fuse\nexport FUSE_SUBTYP=.testerofs\n",
		mntDir,
	)
	require.NoError(t, os.WriteFile(filepath.Join(xfstestsDir, "local.config"), []byte(config), 0644))

	// Step 5: run xfstests.
	t.Log("Running xfstests (this may take several minutes)...")
	cmd := exec.Command("./check", "-fuse", "-E", excludeFile)
	cmd.Dir = xfstestsDir
	cmd.Env = append(os.Environ(), "FSTYP=fuse")
	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Log(output)

	// Parse results.
	if strings.Contains(output, "Passed all") {
		return // success
	}
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "Failures:") || strings.Contains(line, "Failed") {
			t.Fatalf("xfstests reported failures:\n%s", output)
		}
	}
	require.NoError(t, err, "xfstests exited with error")
}

// installMountHelper writes /usr/sbin/mount.fuse.testerofs so that xfstests
// can mount the EROFS image through the standard FUSE mount interface.
func installMountHelper(t *testing.T, leptonBin, img, blob string) {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/bash
DEVICE="$1"
MOUNTPOINT="$2"
[ -z "$MOUNTPOINT" ] && MOUNTPOINT="/tmp/erofs_mount"
[ -z "$DEVICE" ] && DEVICE="testerofs"
ulimit -n 1048576
pkill -f "lepton mount.*${MOUNTPOINT}" 2>/dev/null || true
fusermount -u "${MOUNTPOINT}" 2>/dev/null || true
sleep 0.5
%s mount %s "${MOUNTPOINT}" --blobdev %s --fsname "${DEVICE}" 1>>/tmp/erofs_fuse.log 2>&1 &
for i in $(seq 1 10); do
    mountpoint -q "${MOUNTPOINT}" 2>/dev/null && exit 0
    sleep 0.5
done
echo "ERROR: lepton mount failed to mount within 5 seconds" >&2
exit 1
`, leptonBin, img, blob)

	const helperPath = "/usr/sbin/mount.fuse.testerofs"
	require.NoError(t, os.WriteFile(helperPath, []byte(script), 0755))
}
