package mount

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
)

// Fileio serves an image through `nydus fileio`: the flattened image is
// exported as a file over FUSE and the kernel EROFS driver mounts that file.
type Fileio struct{}

// Name returns "fileio".
func (Fileio) Name() string { return "fileio" }

// Require requires root, kernel 6.12 file-backed EROFS mounts, FUSE, EROFS
// and the fileio subcommand.
func (Fileio) Require(t testing.TB) {
	t.Helper()
	env.RequireRoot(t)
	env.RequireKernel(t, 6, 12, "file-backed EROFS mounts")
	env.RequireFilesystem(t, "fuse")
	env.RequireFilesystem(t, "erofs")
	env.RequireSubcommand(t, "fileio")
}

// Supports reports Cold and Warm: fileio always needs a bootstrap.
func (Fileio) Supports(m Mode) bool { return m != Blob }

// Start runs `nydus fileio` and waits until EROFS is mounted on the export.
func (Fileio) Start(t testing.TB, req Request) (string, *Daemon, func()) {
	t.Helper()
	mnt := filepath.Join(req.Dir, "mnt")

	export := filepath.Join(req.Dir, "export")
	for _, d := range []string{mnt, export} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("create %s: %v", d, err)
		}
	}

	args := []string{"fileio",
		"--bootstrap", req.Image.Bootstrap,
		"--config", req.Config,
		"--export-dir", export,
		"--mountpoint", mnt,
		"--apiserver", "unix://" + req.Socket,
	}

	// Registered first, so they run last: they only matter when the daemon
	// failed to start or died, leaving its mounts behind.
	t.Cleanup(func() {
		Unmount(mnt)
		Unmount(export)
	})

	d := StartDaemon(t, req.Dir, "nydus-fileio", env.Nydus(t), DaemonArgs(args, req, "nydus-fileio")...)
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return IsMountpoint(mnt) })

	return mnt, d, func() {
		// The daemon unmounts EROFS before ending the export; these only
		// matter when it died without running its shutdown path. They are
		// unconditional: a dead daemon's export fails mountpoint(1) checks
		// with ENOTCONN, and Unmount of an unmounted directory is a no-op.
		d.Stop()
		Unmount(mnt)
		Unmount(export)
	}
}
