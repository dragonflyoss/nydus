package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// ublkChunkSize is the chunk size the ublk image is built with.
const ublkChunkSize = 4096

// TestUblkService serves an image as a ublk block device, mounts it with the
// kernel EROFS driver and checks the result matches the same image mounted
// through FUSE. With NYDUS_E2E_UFFD_REQUIRE set, a missing subcommand or driver
// fails the test instead of skipping it.
func TestUblkService(t *testing.T) {
	util.SkipUnlessRoot(t, "ublk block devices")
	requireSubcommand(t, "ublk", "cli,ublk")
	if out, err := exec.Command("modprobe", "ublk_drv").CombinedOutput(); err != nil {
		skipUnlessRequired(t, "ublk_drv is unavailable (needs Linux 6.0+): %s", out)
	}
	if _, err := os.Stat("/dev/ublk-control"); err != nil {
		skipUnlessRequired(t, "/dev/ublk-control is missing: %v", err)
	}
	assert := assert.New(t)

	// Build the image and serve it as a block device.
	workDir := t.TempDir()
	source := filepath.Join(workDir, "corpus")
	bootstrap := filepath.Join(workDir, "image.boot")
	blobDir := filepath.Join(workDir, "blobs")
	cacheDir := filepath.Join(workDir, "cache")
	configPath := filepath.Join(workDir, "config.yaml")
	blockMountpoint := filepath.Join(workDir, "mnt-ublk")
	fuseMountpoint := filepath.Join(workDir, "mnt-fuse")

	corpus.MakeStandardCorpus(t, source)
	util.BuildImage(t, nydusBin, bootstrap, blobDir, source, ublkChunkSize)
	util.WriteLocalBackendConfig(t, configPath, blobDir, cacheDir, "none")
	devicePath := startUblkService(t, bootstrap, configPath, workDir)

	// Mount the device with the kernel driver, and unmount it before the
	// daemon is stopped: the daemon serves I/O for its own device, so an
	// unmount that flushes I/O while it is exiting would hang.
	assert.NoError(os.MkdirAll(blockMountpoint, 0o755))
	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", devicePath, blockMountpoint).CombinedOutput()
	if !assert.NoError(err, "failed to mount %s as erofs: %s", devicePath, out) {
		return
	}
	defer util.Unmount(blockMountpoint)

	// The FUSE mount is the reference implementation of the same image, so any
	// mismatch points at the flattened block address space.
	unmountFuse := util.MountNydusBootstrap(t, nydusBin, bootstrap, blobDir, "", fuseMountpoint)
	defer unmountFuse()
	util.CheckDirectoryEqual(t, fuseMountpoint, blockMountpoint, true)

	entries, err := os.ReadDir(blockMountpoint)
	assert.NoError(err)
	assert.NotEmpty(entries, "ublk/erofs mount is empty")
}

// startUblkService runs `nydus ublk`, logging under workDir, and returns the
// device path it prints on stdout once the device exists. The daemon is
// stopped when t ends, so the caller unmounts the device before then.
func startUblkService(t *testing.T, bootstrap, configPath, workDir string) string {
	t.Helper()
	logDir := filepath.Join(workDir, "logs")
	assert.NoError(t, os.MkdirAll(logDir, 0o755))

	d := &util.Daemon{ConsoleLog: filepath.Join(workDir, "ublk.console.log"), LogDir: logDir}
	d.Start(t, exec.Command(nydusBin, "ublk",
		"--bootstrap", bootstrap,
		"--config", configPath,
		"--log-dir", logDir,
	))
	t.Cleanup(func() { d.Stop() })

	// The daemon also logs to stdout, so scan for the device path line rather
	// than assuming it comes first.
	var devicePath string
	d.WaitReady(t, func() bool {
		for _, line := range strings.Split(d.Logs(), "\n") {
			if line = strings.TrimSpace(line); strings.HasPrefix(line, "/dev/ublkb") {
				devicePath = line
				return true
			}
		}

		return false
	})
	assert.Eventually(t, func() bool {
		_, err := os.Stat(devicePath)
		return err == nil
	}, 10*time.Second, 200*time.Millisecond, "%s did not appear within 10s", devicePath)

	return devicePath
}
