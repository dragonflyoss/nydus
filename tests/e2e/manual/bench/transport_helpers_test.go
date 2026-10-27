//go:build manual

package bench

// Start helpers for the modes internal/mount has no adapter for. Each serves
// the image from a fresh work directory and cache, like mount.Mount does.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

const mountTimeout = 60 * time.Second

// workspace creates a fresh work directory with a mountpoint, an empty
// cache and a local-backend config over the image's blobs. Prefetch stays
// off: a background prefetch would warm the cache mid-run.
func workspace(t *testing.T, img fixture.Image) (dir, mnt, cache, config string) {
	t.Helper()
	dir = env.WorkDir(t)
	mnt = filepath.Join(dir, "mnt")
	cache = filepath.Join(dir, "cache")
	for _, d := range []string{mnt, cache} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	config = mount.LocalConfig(img.BlobDir, cache).Write(t, dir, "config.json")
	return dir, mnt, cache, config
}

func startNbd(t *testing.T, nydus string, img fixture.Image, device string) *served {
	t.Helper()
	dir, mnt, cache, config := workspace(t, img)
	d := mount.StartDaemon(t, dir, "nydus-nbd", nydus, "nbd",
		"--bootstrap", img.Bootstrap,
		"--config", config,
		"--device", device,
		"--mountpoint", mnt,
		"--log-level", "info",
		"--log-dir", mount.LogDir(dir, "nydus-nbd"),
	)
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })
	return &served{root: mnt, cache: cache, stop: func() {
		d.Stop()
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
		waitNbdRelease(t, device)
	}}
}

// findFreeNbdDevice returns an unattached /dev/nbdN, loading the nbd module
// if needed.
func findFreeNbdDevice() (string, error) {
	if _, err := os.Stat("/dev/nbd0"); err != nil {
		if exec.Command("modprobe", "nbd").Run() != nil {
			return "", fmt.Errorf("nbd module not available and modprobe failed: %w", err)
		}
	}
	for i := range 16 {
		dev := fmt.Sprintf("/dev/nbd%d", i)
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		if data, err := os.ReadFile(fmt.Sprintf("/sys/block/nbd%d/size", i)); err == nil && strings.TrimSpace(string(data)) == "0" {
			return dev, nil
		}
	}
	return "", fmt.Errorf("nbd0-nbd15 are all in use")
}

// waitNbdRelease waits until the kernel reports device detached (sysfs size
// back to 0), so the next mount can attach it again.
func waitNbdRelease(t *testing.T, device string) {
	t.Helper()
	sysfs := filepath.Join("/sys/block", filepath.Base(device), "size")
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(sysfs)
		return err != nil || strings.TrimSpace(string(data)) == "0"
	}, 10*time.Second, 100*time.Millisecond, "%s not released after the daemon exited", device)
}

func startUblk(t *testing.T, nydus string, img fixture.Image) *served {
	t.Helper()
	dir, mnt, cache, config := workspace(t, img)
	socket := mount.SocketPath(t)
	d := mount.StartDaemon(t, dir, "nydus-ublk", nydus, "ublk",
		"--bootstrap", img.Bootstrap,
		"--config", config,
		"--log-level", "info",
		"--log-dir", mount.LogDir(dir, "nydus-ublk"),
		"--apiserver", "unix://"+socket,
	)
	// The daemon prints its /dev/ublkbN on stdout once ready.
	var dev string
	d.WaitFor(t, mountTimeout, "a /dev/ublkb device", func() bool {
		for _, line := range strings.Split(d.Log(), "\n") {
			if line = strings.TrimSpace(line); strings.HasPrefix(line, "/dev/ublkb") {
				dev = line
				return true
			}
		}
		return false
	})
	d.WaitFor(t, 10*time.Second, dev+" to appear", func() bool {
		_, err := os.Stat(dev)
		return err == nil
	})
	fixture.Run(t, "mount", "-t", "erofs", "-o", "ro", dev, mnt)
	return &served{root: mnt, api: mount.NewAPI(socket), cache: cache, stop: func() {
		// Unmount first: the daemon serves the I/O of its own block device,
		// so unmounting while it exits would deadlock.
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
		d.Stop()
	}}
}

// ublkAvailable reports whether ublk_drv loads and its control device
// exists.
func ublkAvailable() bool {
	if exec.Command("modprobe", "ublk_drv").Run() != nil {
		return false
	}
	_, err := os.Stat("/dev/ublk-control")
	return err == nil
}

func startFanotify(t *testing.T, nydus string, img fixture.Image) *served {
	t.Helper()
	dir, mnt, cache, config := workspace(t, img)
	d := mount.StartDaemon(t, dir, "nydus-fanotify", nydus, "fanotify",
		"--bootstrap", img.Bootstrap,
		"--config", config,
		"--mountpoint", mnt,
		"--log-level", "info",
		"--log-dir", mount.LogDir(dir, "nydus-fanotify"),
	)
	d.WaitFor(t, mountTimeout, "the fanotify event loop", func() bool {
		return mount.IsMountpoint(mnt) && strings.Contains(d.Log()+d.FileLog(), "event loop ready")
	})
	return &served{root: mnt, cache: cache, stop: func() {
		d.Stop()
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	}}
}

// lookupErofsfuse finds the C erofsfuse: EROFS_C_FUSE, the usual install
// locations, then PATH.
func lookupErofsfuse() (string, error) {
	if p := os.Getenv("EROFS_C_FUSE"); p != "" {
		if st, err := os.Stat(p); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			return "", fmt.Errorf("EROFS_C_FUSE=%s is not an executable", p)
		}
		return p, nil
	}
	for _, p := range []string{"/usr/bin/erofsfuse", "/usr/local/bin/erofsfuse"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("erofsfuse"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("erofsfuse not found, set EROFS_C_FUSE=path to add its column")
}

// startErofsfuse mounts the bootstrap with the C erofsfuse reading the blob
// directly: no daemon of ours, no cache.
func startErofsfuse(t *testing.T, bin string, img fixture.Image) *served {
	t.Helper()
	dir := env.WorkDir(t)
	mnt := filepath.Join(dir, "mnt")
	require.NoError(t, os.MkdirAll(mnt, 0o755))
	d := mount.StartDaemon(t, dir, "erofsfuse", bin, "--device="+img.Blob(), img.Bootstrap, mnt, "-f")
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })
	return &served{root: mnt, stop: func() {
		mount.Unmount(mnt)
		d.Stop()
	}}
}

// v2Image is the corpus built by nydus v2 for the v2-fuse column.
type v2Image struct {
	nydusd, bootstrap, blobDir string
}

// buildV2Image builds src with the nydus v2 builder when
// NYDUSFS_BENCH_V2_NYDUSD and NYDUSFS_BENCH_V2_IMAGE_BIN are both set, and
// returns nil otherwise.
func buildV2Image(t *testing.T, work, src string) *v2Image {
	t.Helper()
	nydusd, builder := os.Getenv("NYDUSFS_BENCH_V2_NYDUSD"), os.Getenv("NYDUSFS_BENCH_V2_IMAGE_BIN")
	if nydusd == "" || builder == "" {
		return nil
	}
	t.Log("Building the nydus v2 (rafs v6) image...")
	img := &v2Image{
		nydusd:    nydusd,
		bootstrap: filepath.Join(work, "v2.boot"),
		blobDir:   filepath.Join(work, "v2-blobs"),
	}
	require.NoError(t, os.MkdirAll(img.blobDir, 0o755))
	fixture.Run(t, builder, "create",
		"--fs-version", "6", "--compressor", "zstd",
		"--blob-id", "v2blob",
		"--blob", filepath.Join(img.blobDir, "v2blob"),
		"--external-blob", filepath.Join(work, "v2.ext"),
		"--bootstrap", img.bootstrap,
		src)
	return img
}

func startV2Fuse(t *testing.T, img *v2Image) *served {
	t.Helper()
	dir := env.WorkDir(t)
	mnt := filepath.Join(dir, "mnt")
	cache := filepath.Join(dir, "cache")
	for _, d := range []string{mnt, cache} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	config := filepath.Join(dir, "v2.json")
	require.NoError(t, os.WriteFile(config, fmt.Appendf(nil, `{
  "device": {
    "backend": { "type": "localfs", "config": { "dir": %q } },
    "cache": { "type": "blobcache", "config": { "work_dir": %q } }
  },
  "mode": "direct",
  "digest_validate": false,
  "enable_xattr": true,
  "iostats_files": false
}`, img.blobDir, cache), 0o644))
	d := mount.StartDaemon(t, dir, "nydusd-v2", img.nydusd,
		"--config", config,
		"--bootstrap", img.bootstrap,
		"--mountpoint", mnt,
		"--log-level", "error",
	)
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })
	return &served{root: mnt, cache: cache, stop: func() {
		d.Stop()
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	}}
}
