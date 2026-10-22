package mount

import (
	"os"
	"path/filepath"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
)

// mountTimeout bounds how long a daemon may take to mount. Daemons fail
// fast when they exit, so this only matters for a hang.
const mountTimeout = 60 * time.Second

// FUSE serves an image through `nydus fuse`.
type FUSE struct{}

func (FUSE) Name() string { return "fuse" }

func (FUSE) Require(t env.TB) {
	t.Helper()
	env.RequireRoot(t)
	env.RequireFilesystem(t, "fuse")
}

func (FUSE) Supports(Mode) bool { return true }

func (FUSE) Start(t env.TB, req Request) (string, *Daemon, func()) {
	t.Helper()
	mnt := filepath.Join(req.Dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("create %s: %v", mnt, err)
	}
	args := []string{"fuse", "--mountpoint", mnt, "--apiserver", "unix://" + req.Socket}
	if req.Mode == Blob {
		args = append(args, "--blob", req.Image.Blob())
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

// DaemonArgs appends the log flags for the daemon called name and the
// request's extra args.
func DaemonArgs(args []string, req Request, name string) []string {
	args = append(args, "--log-level", "info", "--log-dir", LogDir(req.Dir, name))
	return append(args, req.Args...)
}
