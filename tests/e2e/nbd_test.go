package e2e

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// nbdReadFailurePattern matches the daemon's log line for a failed NBD read.
var nbdReadFailurePattern = regexp.MustCompile(`nbd: read .* failed:`)

// TestNbd boots `nydus nbd` on a free NBD device against a local blob
// directory, mounts the device as EROFS and runs the shared service cases:
// cold reads through the NBD socket are byte-exact and demand-paged, the
// warm cache survives a restart and SIGTERM shuts the daemon down cleanly.
// It needs root, the nbd and erofs kernel modules and a nydus built with the
// nbd feature.
func TestNbd(t *testing.T) {
	util.SkipUnlessRoot(t, "CAP_SYS_ADMIN for the nbd ioctls and the mount")
	util.SkipUnlessSubcommand(t, nydusBin, "nbd", "cli,nbd")
	if !util.ErofsSupported() {
		t.Skip("erofs not in /proc/filesystems")
	}
	device, err := util.FindFreeNbdDevice()
	if err != nil {
		t.Skipf("no free NBD device: %v (try: modprobe nbd)", err)
	}

	// Build the image with 4 MiB chunks and point the daemon at the blob
	// directory as its local backend.
	suite := newServiceSuite(t)
	util.BuildImage(t, nydusBin, suite.bootstrap, suite.blobDir, suite.source, 4*1024*1024)
	util.WriteLocalBackendConfig(t, suite.configPath, suite.blobDir, suite.cacheDir, "none")
	suite.args = []string{
		nydusBin, "nbd",
		"--bootstrap", suite.bootstrap,
		"--config", suite.configPath,
		"--device", device,
		"--mountpoint", suite.mountpoint,
		"--log-level", "debug",
		"--log-dir", suite.LogDir,
	}
	suite.afterStop = func(t *testing.T) { util.WaitNbdDetached(t, device) }
	suite.readyPattern = `mounted `
	suite.shutdownPattern = `received signal`
	suite.startCold(t)

	suite.run(t, func(t *testing.T) {
		assert := assert.New(t)
		assert.True(util.IsMountpoint(suite.mountpoint), "mountpoint is not live")
		assert.Greater(suite.CountLogs(`nbd service attached`), 0, "device attachment not logged")

		// EROFS metadata reads come from the local bootstrap, not the blob
		// cache: no whole-blob prefetch may have happened. Some blob-tail
		// allocation is expected before any file read, since the core
		// validates each blob's footer on its first flat-range resolve and
		// the kernel's block-device open scans the device head and tail.
		for _, blobData := range suite.blobDataFiles() {
			assert.Less(util.AllocatedBytes(t, blobData), int64(16<<20), "cache %s holds more than fetch-size fills before any file read", blobData)
		}
	}, func(t *testing.T) {
		assert := assert.New(t)
		assert.Equal(0, suite.CountLogs(`nbd: invalid request magic`), "bad-magic errors for legit reads")
		assert.Equal(0, suite.CountLogs(`nbd: short read`), "short-read errors for legit reads")
		assert.Equal(0, util.CountMatchingLines(suite.Logs(), nbdReadFailurePattern), "read failures against the local backend")
		assert.Equal(0, suite.CountLogs(`nbd: unsupported request type`), "unsupported-type errors for legit reads")
	})
}

func TestNbdReadFailurePattern(t *testing.T) {
	logs := strings.Join([]string{
		"INFO nbd service attached to /dev/nbd0",
		"WARN nbd: failed to read request header: unexpected EOF",
		"WARN nbd: failed to handle request: broken pipe",
		"WARN nbd: read [0x0, +4096) failed: input/output error",
	}, "\n")

	assert.Equal(t, 1, util.CountMatchingLines(logs, nbdReadFailurePattern))
}
