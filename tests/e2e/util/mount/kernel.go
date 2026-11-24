package mount

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const erofsBlockSize = 4096

// Kernel mounts a native image with the kernel EROFS driver alone, over
// read-only loop devices of the bootstrap and its blobs: no nydus process
// serves the mount, so what it reads is what the builder wrote.
type Kernel struct{}

// Name returns "kernel".
func (Kernel) Name() string { return "kernel" }

// Require checks what MustHaveEROFS does of any layout.
func (Kernel) Require(t testing.TB) {
	t.Helper()
	MustHaveEROFS(t, fixture.Layout{})
}

// Supports reports Cold alone: there is no cache to warm, and a blob alone
// is not a mountable image.
func (Kernel) Supports(m Mode) bool { return m == Cold }

// Traits reports that no daemon serves the mount.
func (Kernel) Traits() Traits { return Traits{Daemonless: true} }

// Start mounts the image and returns no daemon.
func (Kernel) Start(t testing.TB, req Request) (string, *Daemon, func()) {
	t.Helper()
	MustHaveEROFS(t, req.Image.Layout)

	mnt := filepath.Join(req.Dir, "mnt")
	EROFS(t, mnt, req.Image.Bootstrap, DeviceFiles(t, req.Image.Bootstrap, req.Image.BlobDir, ""))

	return mnt, nil, func() { Unmount(mnt) }
}

// MustHaveEROFS skips t unless the kernel mounts EROFS images of layout over
// loop devices.
func MustHaveEROFS(t testing.TB, layout fixture.Layout) {
	t.Helper()
	env.MustHaveRoot(t)
	env.MustHaveKernel(t, 5, 16, "EROFS chunk-based files on extra devices")

	switch layout.Compressor() {
	case "erofs-lz4":
		env.MustHaveKernel(t, 6, 1, "EROFS LZ4 fragments")

	case "erofs-zstd":
		env.MustHaveKernel(t, 6, 10, "EROFS zstd")
	}

	env.MustHaveFilesystem(t, "erofs")
	env.LookPath(t, "losetup")

	if os.Getpagesize() != erofsBlockSize {
		env.Skipf(t, "EROFS images use 4KiB blocks, the page size is %d", os.Getpagesize())
	}
}

// EROFS mounts bootstrap at mnt with the kernel EROFS driver, over read-only
// loop devices of the bootstrap and of devices, its extra devices in device
// table order. The mount and the loop devices are released when t ends. The
// caller has checked MustHaveEROFS.
func EROFS(t testing.TB, mnt, bootstrap string, devices []string) {
	t.Helper()
	losetup := env.LookPath(t, "losetup")

	if !assert.NoError(t, os.MkdirAll(mnt, 0o755)) {
		t.FailNow()
	}

	attach := func(path string) string {
		dev := strings.TrimSpace(env.Run(t, losetup, "--find", "--show", "--read-only", path))

		t.Cleanup(func() {
			assert.NoError(t, exec.Command(losetup, "--detach", dev).Run())
		})

		return dev
	}

	primary := attach(bootstrap)
	var opts []string

	for _, path := range devices {
		opts = append(opts, "device="+attach(path))
	}

	t.Cleanup(func() { Unmount(mnt) })

	if !assert.NoError(t, unix.Mount(primary, mnt, "erofs", unix.MS_RDONLY, strings.Join(opts, ","))) {
		t.FailNow()
	}
}

// DeviceFiles returns the files in dir backing the extra devices of
// bootstrap, in device table order: each is named by its device tag plus
// suffix.
func DeviceFiles(t testing.TB, bootstrap, dir, suffix string) []string {
	t.Helper()
	tags, err := erofs.DeviceTags(bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	files := make([]string, len(tags))

	for i, tag := range tags {
		files[i] = filepath.Join(dir, tag+suffix)
		assert.FileExists(t, files[i])
	}

	return files
}
