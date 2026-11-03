// Package fanotify serves images through `nydus fanotify`: the daemon
// mounts the bootstrap as file-backed EROFS whose blob devices are the
// sparse cache files, and fills them from fanotify pre-content events as the
// kernel reads them.
package fanotify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

const (
	daemonName   = "nydus-fanotify"
	mountTimeout = 60 * time.Second
)

// Fanotify serves an image through `nydus fanotify`.
type Fanotify struct{}

func (Fanotify) Name() string { return "fanotify" }

func (Fanotify) Require(t testing.TB) {
	t.Helper()
	env.RequireRoot(t)
	env.RequireKernel(t, 6, 15, "fanotify pre-content events with range info")
	env.RequireFilesystem(t, "erofs")
	env.RequireSubcommand(t, "fanotify")
	// Mounts keep their caches under TMPDIR.
	requireDiskFS(t, os.TempDir())
}

// Supports reports Cold and Warm: the daemon mounts a bootstrap.
func (Fanotify) Supports(m mount.Mode) bool { return m != mount.Blob }

// Traits reports that the daemon mounts EROFS itself but serves no apiserver.
func (Fanotify) Traits() mount.Traits { return mount.Traits{API: false, OwnsMount: true} }

func (Fanotify) Start(t testing.TB, req mount.Request) (string, *mount.Daemon, func()) {
	t.Helper()
	return start(t, req, nil)
}

// start runs the daemon, under the wrapper command when one is given.
func start(t testing.TB, req mount.Request, wrapper []string) (string, *mount.Daemon, func()) {
	t.Helper()
	requireDiskFS(t, cacheDir(t, req.Config))
	mnt := filepath.Join(req.Dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("create %s: %v", mnt, err)
	}
	// Registered before the daemon so it runs after the daemon stopped.
	t.Cleanup(func() {
		mount.Unmount(mnt)
	})

	args := mount.DaemonArgs([]string{"fanotify",
		"--bootstrap", req.Image.Bootstrap,
		"--config", req.Config,
		"--mountpoint", mnt,
	}, req, daemonName)

	bin := env.Nydus(t)
	if len(wrapper) > 0 {
		args = slices.Concat(wrapper[1:], []string{bin}, args)
		bin = wrapper[0]
	}

	d := mount.StartDaemon(t, req.Dir, daemonName, bin, args...)

	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool {
		return mount.IsMountpoint(mnt) && strings.Contains(d.Log(), "mounted file-backed EROFS")
	})

	return mnt, d, func() {
		// The daemon unmounts before it releases the fanotify group; the
		// fallback only matters when it died without its shutdown path.
		d.Stop()
		mount.Unmount(mnt)
	}
}

// cacheDir returns the storage directory of the config at path.
func cacheDir(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var cfg mount.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg.Storage == nil || cfg.Storage.Dir == "" {
		t.Fatalf("%s sets no cache directory", path)
	}

	return cfg.Storage.Dir
}

// requireDiskFS requires dir to be on a filesystem whose page cache the
// pre-content hook covers: tmpfs raises no pre-content events.
func requireDiskFS(t testing.TB, dir string) {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatalf("statfs %s: %v", dir, err)
	}

	env.Require(t, st.Type != unix.TMPFS_MAGIC && st.Type != unix.RAMFS_MAGIC,
		"%s is on tmpfs, which raises no fanotify pre-content events; point TMPDIR at a disk filesystem", dir)
}
