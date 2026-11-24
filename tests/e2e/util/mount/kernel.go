package mount

import (
	"fmt"
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

// Kernel mounts a native image with the kernel EROFS driver alone: the
// bootstrap and its blobs are attached as read-only loop devices and no
// nydus process serves the mount, so what it reads is what the builder wrote.
type Kernel struct{}

// Name returns "kernel".
func (Kernel) Name() string { return "kernel" }

// Require requires what RequireEROFS does of any image.
func (Kernel) Require(t testing.TB) {
	t.Helper()
	RequireEROFS(t, fixture.Layout{})
}

// Supports reports Cold alone: there is no cache to warm, and a blob alone
// is not a mountable image.
func (Kernel) Supports(m Mode) bool { return m == Cold }

// Serves reports the native layouts: the kernel cannot decode nydus chunk
// groups.
func (Kernel) Serves(l fixture.Layout) bool { return l.Native }

// Traits reports that no daemon serves the mount.
func (Kernel) Traits() Traits { return Traits{Daemonless: true} }

// Start mounts the image and returns no daemon.
func (Kernel) Start(t testing.TB, req Request) (string, *Daemon, func()) {
	t.Helper()
	RequireEROFS(t, req.Image.Layout)

	mnt := filepath.Join(req.Dir, "mnt")
	EROFS(t, mnt, req.Image.Bootstrap, DeviceFiles(t, req.Image.Bootstrap, req.Image.BlobDir, ""))

	return mnt, nil, func() { Unmount(mnt) }
}

// RequireEROFS skips t unless it can mount EROFS images of layout over loop
// devices.
func RequireEROFS(t testing.TB, layout fixture.Layout) {
	t.Helper()
	if why := erofsUnavailable(layout); why != "" {
		env.Skipf(t, "%s", why)
	}
}

// KernelReads reports whether Kernel can mount images of layout. A check
// that wants a daemonless mount besides another is left out where it cannot,
// and fails under CI.
func KernelReads(t testing.TB, layout fixture.Layout) bool {
	t.Helper()
	if !layout.Native {
		return false
	}

	why := erofsUnavailable(layout)
	if why != "" {
		env.Omitf(t, "the kernel cannot mount %s images: %s", layout.Name, why)
	}

	return why == ""
}

// erofsUnavailable returns why EROFS images of layout cannot be mounted over
// loop devices, or "" when they can.
func erofsUnavailable(layout fixture.Layout) string {
	major, minor, feature := 5, 16, "EROFS chunk-based files on extra devices"

	switch layout.Compressor() {
	case "erofs-lz4":
		major, minor, feature = 6, 1, "EROFS LZ4 fragments"

	case "erofs-zstd":
		major, minor, feature = 6, 10, "EROFS zstd"
	}

	switch {
	case os.Geteuid() != 0:
		return "must run as root"

	case !env.KernelAtLeast(major, minor):
		gotMajor, gotMinor := env.KernelVersion()
		return fmt.Sprintf("kernel %d.%d < %d.%d: %s", gotMajor, gotMinor, major, minor, feature)

	case !env.HasFilesystem("erofs"):
		return "kernel lacks erofs support"

	case os.Getpagesize() != erofsBlockSize:
		return fmt.Sprintf("EROFS images use 4KiB blocks, the page size is %d", os.Getpagesize())
	}

	if _, err := exec.LookPath("losetup"); err != nil {
		return "losetup is not installed"
	}

	return ""
}

// EROFS mounts bootstrap at mnt with the kernel EROFS driver, over read-only
// loop devices of the bootstrap and of devices, its extra devices in device
// table order. The mount and the loop devices are released when t ends. The
// caller has checked RequireEROFS or KernelReads.
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
