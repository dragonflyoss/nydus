// Package fanotify serves images through `nydus fanotify`: the daemon
// mounts the bootstrap as file-backed EROFS whose blob devices are the
// sparse cache files, and fills them from fanotify pre-content events as the
// kernel reads them.
package fanotify

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"golang.org/x/sys/unix"
)

const (
	daemonName = "nydus-fanotify"
	// mountTimeout bounds how long the daemon may take to mount.
	mountTimeout = 60 * time.Second
)

// Fanotify serves an image through `nydus fanotify`.
type Fanotify struct{}

func (Fanotify) Name() string { return "fanotify" }

func (Fanotify) Require(t env.TB) {
	t.Helper()
	env.RequireRoot(t)
	env.RequireKernel(t, 6, 15, "fanotify pre-content events with range info")
	env.RequireFilesystem(t, "erofs")
	requireSubcommand(t, "fanotify")
	// Mounts keep their caches under TMPDIR.
	requireDiskFS(t, os.TempDir())
}

// Supports reports Cold and Warm: the daemon mounts a bootstrap.
func (Fanotify) Supports(m mount.Mode) bool { return m != mount.Blob }

// Traits: the daemon mounts EROFS itself but serves no apiserver.
func (Fanotify) Traits() mount.Traits { return mount.Traits{API: false, OwnsMount: true} }

func (Fanotify) Start(t env.TB, req mount.Request) (string, *mount.Daemon, func()) {
	t.Helper()
	return start(t, req, nil)
}

// start runs the daemon, under the wrapper command when one is given.
func start(t env.TB, req mount.Request, wrapper []string) (string, *mount.Daemon, func()) {
	t.Helper()
	requireDiskFS(t, cacheDir(t, req.Config))
	mnt := filepath.Join(req.Dir, "mnt")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatalf("create %s: %v", mnt, err)
	}
	// Registered before the daemon so it runs after the daemon stopped.
	t.Cleanup(func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	})
	args := mount.DaemonArgs([]string{"fanotify",
		"--bootstrap", req.Image.Bootstrap,
		"--config", req.Config,
		"--mountpoint", mnt,
	}, req, daemonName)
	bin := env.Nydus(t)
	if len(wrapper) > 0 {
		args = append(append(append([]string{}, wrapper[1:]...), bin), args...)
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
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	}
}

// cacheDir returns the storage directory of the config at path.
func cacheDir(t env.TB, path string) string {
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
func requireDiskFS(t env.TB, dir string) {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatalf("statfs %s: %v", dir, err)
	}
	env.Require(t, st.Type != unix.TMPFS_MAGIC && st.Type != unix.RAMFS_MAGIC,
		"%s is on tmpfs, which raises no fanotify pre-content events; point TMPDIR at a disk filesystem", dir)
}

var subcommands sync.Map

// requireSubcommand requires a nydus binary built with the feature that
// provides the subcommand.
func requireSubcommand(t env.TB, name string) {
	t.Helper()
	nydus := env.Nydus(t)
	ok, cached := subcommands.Load(name)
	if !cached {
		ok = exec.Command(nydus, name, "--help").Run() == nil
		subcommands.Store(name, ok)
	}
	env.Require(t, ok.(bool), "%s lacks the %s subcommand (build with FEATURES=...,%s)", nydus, name, name)
}
