package mount

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
)

// FUSE serves an image through `nydus fuse`.
type FUSE struct{}

// Name returns "fuse".
func (FUSE) Name() string { return "fuse" }

// Require requires root and FUSE.
func (FUSE) Require(t testing.TB) {
	t.Helper()
	env.MustHaveRoot(t)
	env.MustHaveFilesystem(t, "fuse")
}

// Supports reports true for every mode, Blob included.
func (FUSE) Supports(Mode) bool { return true }

// Start runs `nydus fuse` and waits until the filesystem is mounted.
func (FUSE) Start(t testing.TB, req Request) (string, *Daemon, func()) {
	t.Helper()
	mnt := filepath.Join(req.Dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("create %s: %v", mnt, err)
	}

	args := []string{"fuse", "--mountpoint", mnt, "--apiserver", "unix://" + req.Socket}
	if req.Mode == Blob {
		args = append(args, "--blob", req.Image.Blob(t))
	} else {
		args = append(args, "--bootstrap", req.Image.Bootstrap, "--config", req.Config)
	}
	// Registered first, so it runs last: it only matters when the daemon
	// failed to start or died, leaving its mount behind.
	t.Cleanup(func() { Unmount(mnt) })
	d := StartDaemon(t, req.Dir, "nydus-fuse", env.Nydus(t), DaemonArgs(args, req, "nydus-fuse")...)
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return IsMountpoint(mnt) })

	return mnt, d, func() {
		Unmount(mnt)
		d.Stop()
	}
}
