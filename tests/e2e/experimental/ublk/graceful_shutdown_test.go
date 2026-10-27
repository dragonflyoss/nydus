package ublk

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

// TestGracefulShutdown unmounts the device and stops the daemon with
// SIGTERM: it exits cleanly and deletes its block device.
func TestGracefulShutdown(t *testing.T) {
	t.Parallel()
	Ublk{}.Require(t)
	m := mount.Mount(t, Ublk{}, fixture.Get(t, "zstd-4k"), mount.Options{})
	mount.ReadAll(t, m.Root)
	dev := devicePath(m.Daemon.Log())
	require.NotEmpty(t, dev)

	// The daemon serves the unmount's own I/O, so it has to come first.
	mount.Unmount(m.Root)
	require.False(t, mount.IsMountpoint(m.Root), "%s still mounted", m.Root)
	m.Daemon.Signal(syscall.SIGTERM)
	select {
	case <-m.Daemon.Exited():
	case <-time.After(20 * time.Second):
		t.Fatalf("daemon still running 20s after SIGTERM")
	}
	require.Zero(t, m.Daemon.ExitCode(), "daemon exit code")
	require.Contains(t, m.Daemon.Log(), "received signal")
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join("/sys/block", filepath.Base(dev)))
		return os.IsNotExist(err)
	}, 10*time.Second, 100*time.Millisecond, "%s not deleted after the daemon exited", dev)
}
