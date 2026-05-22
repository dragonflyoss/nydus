package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/lepton/tests/integration/texture"
	"github.com/stretchr/testify/require"
)

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

	setupXfstests(t, xfstestsDir)
	leptonBin := mustLookupExecutable(t, "lepton")

	t.Log("Generating corpus...")
	texture.MakeStandardCorpus(t, corpusDir)
	_ = os.Remove(imagePath)
	_ = os.Remove(blobdev)

	t.Log("Building LeptonFS image...")
	buildLeptonFSImage(t, leptonBin, imagePath, blobdev, corpusDir, 4096)

	installMountHelper(t, leptonBin, imagePath, blobdev)

	require.NoError(t, os.MkdirAll(mntDir, 0755))
	config := fmt.Sprintf(
		"export TEST_DEV=testleptonfs\nexport TEST_DIR=%s\nexport FSTYP=fuse\nexport FUSE_SUBTYP=.testleptonfs\n",
		mntDir,
	)
	require.NoError(t, os.WriteFile(filepath.Join(xfstestsDir, "local.config"), []byte(config), 0644))

	excludeFile, err := filepath.Abs(filepath.Join("..", "scripts", "xfstests_leptonfs.exclude"))
	require.NoError(t, err)
	require.FileExists(t, excludeFile)

	t.Log("Running xfstests (this may take several minutes)...")
	cmd := exec.Command("./check", "-fuse", "-E", excludeFile)
	cmd.Dir = xfstestsDir
	cmd.Env = append(os.Environ(), "FSTYP=fuse")
	out, err := cmd.CombinedOutput()
	output := string(out)
	t.Log(output)
	require.NoError(t, err, "xfstests exited with error")

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
	t.Helper()

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
pkill -f "lepton fuse.*${MOUNTPOINT}" 2>/dev/null || true
fusermount -u "${MOUNTPOINT}" 2>/dev/null || true
sleep 0.5
%s fuse --bootstrap %s --blob-dir %s --mountpoint "${MOUNTPOINT}" --fsname "${DEVICE}" 1>>/tmp/leptonfs.log 2>&1 &
for i in $(seq 1 20); do
    mountpoint -q "${MOUNTPOINT}" 2>/dev/null && exit 0
    sleep 0.5
done
echo "ERROR: lepton fuse failed to mount within 10 seconds" >&2
exit 1
`, leptonBin, imagePath, filepath.Dir(blobdev))

	const helperPath = "/usr/local/bin/testleptonfs"
	require.NoError(t, os.WriteFile(helperPath, []byte(script), 0755))
}
