//go:build manual

package bench

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/experimental/fanotify"
	"github.com/dragonflyoss/nydus/tests/e2e/experimental/nbd"
	"github.com/dragonflyoss/nydus/tests/e2e/experimental/ublk"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const mountTimeout = 60 * time.Second

type mode struct {
	name  string
	skip  string
	start func(t testing.TB) *served
}

type served struct {
	root  string
	api   *mount.API
	cache string
	stop  func()
}

func adapterMode(name string, a mount.Adapter, img fixture.Image, args ...string) *mode {
	return &mode{name: name, start: func(t testing.TB) *served {
		m := mount.Mount(t, a, img, mount.Options{Mode: mount.Cold, Args: args})
		return &served{root: m.Root, api: m.API, cache: m.CacheDir, stop: m.Unmount}
	}}
}

func modes(t testing.TB, nydus string, img fixture.Image, v2 *v2Image, fileioNoWarmColumn bool) []*mode {
	t.Helper()
	subcommand := func(sub string) string {
		if !env.HasSubcommand(t, sub) {
			return fmt.Sprintf("nydus lacks the %s subcommand (build with --features cli,%s)", sub, sub)
		}

		return ""
	}

	const noErofs = "kernel lacks EROFS support"
	major, minor := env.KernelVersion()

	fuse := adapterMode("fuse", mount.FUSE{}, img)
	if fuse.skip = subcommand("fuse"); fuse.skip == "" && !env.HasFilesystem("fuse") {
		fuse.skip = "kernel lacks FUSE support"
	}

	nbdMode := adapterMode("nbd", nbd.NBD{}, img)
	if nbdMode.skip = subcommand("nbd"); nbdMode.skip == "" && !env.HasFilesystem("erofs") {
		nbdMode.skip = noErofs
	}

	ublkMode := adapterMode("ublk", ublk.Ublk{}, img)
	if ublkMode.skip = subcommand("ublk"); ublkMode.skip == "" && !env.HasFilesystem("erofs") {
		ublkMode.skip = noErofs
	}

	fan := adapterMode("fanotify", fanotify.Fanotify{}, img)
	if fan.skip = subcommand("fanotify"); fan.skip == "" && !env.KernelAtLeast(6, 15) {
		fan.skip = fmt.Sprintf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", major, minor)
	}

	fileioSkip := subcommand("fileio")

	switch {
	case fileioSkip != "":

	case !env.HasFilesystem("erofs"):
		fileioSkip = noErofs

	case !env.KernelAtLeast(6, 12):
		fileioSkip = fmt.Sprintf("kernel %d.%d < 6.12: CONFIG_EROFS_FS_BACKED_BY_FILE unavailable", major, minor)

	case !env.HasFilesystem("fuse"):
		fileioSkip = "kernel lacks FUSE support"
	}

	fileio := adapterMode("fileio", mount.Fileio{}, img, "--warm-bootstrap", "true", "--direct-io", "true")
	fileio.skip = fileioSkip

	fileioNoWarm := adapterMode("fileio-nowarm", mount.Fileio{}, img, "--warm-bootstrap", "false", "--direct-io", "true")
	if fileioNoWarm.skip = fileioSkip; fileioNoWarm.skip == "" && !fileioNoWarmColumn {
		fileioNoWarm.skip = "set NYDUS_E2E_BENCH_FILEIO_NOWARM=1 to add the fileio-nowarm column"
	}

	fileioBuffered := adapterMode("fileio-buffered", mount.Fileio{}, img, "--warm-bootstrap", "true", "--direct-io", "false")
	fileioBuffered.skip = fileioSkip

	erofsfuse := &mode{name: "erofsfuse"}

	if bin, err := lookupErofsfuse(); err != nil {
		erofsfuse.skip = err.Error()
	} else {
		erofsfuse.start = func(t testing.TB) *served { return startErofsfuse(t, bin, img) }
	}

	v2fuse := &mode{name: "v2-fuse", skip: "set NYDUS_E2E_BENCH_V2_NYDUSD and NYDUS_E2E_BENCH_V2_IMAGE_BIN to add the v2 column"}

	if v2 != nil {
		v2fuse.skip = ""
		v2fuse.start = func(t testing.TB) *served { return v2.startV2Fuse(t) }
	}

	return []*mode{v2fuse, fuse, nbdMode, ublkMode, fan, fileio, fileioNoWarm, fileioBuffered, erofsfuse}
}

func lookupErofsfuse() (string, error) {
	if p := os.Getenv("NYDUS_E2E_BENCH_EROFSFUSE"); p != "" {
		if st, err := os.Stat(p); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			return "", fmt.Errorf("NYDUS_E2E_BENCH_EROFSFUSE=%s is not an executable", p)
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

	return "", fmt.Errorf("erofsfuse not found, set NYDUS_E2E_BENCH_EROFSFUSE=path to add its column")
}

func startErofsfuse(t testing.TB, bin string, img fixture.Image) *served {
	t.Helper()
	dir := env.WorkDir(t)
	mnt := filepath.Join(dir, "mnt")
	if !assert.NoError(t, os.MkdirAll(mnt, 0o755)) {
		t.FailNow()
	}

	d := mount.StartDaemon(t, dir, "erofsfuse", bin, "--device="+img.Blob(t), img.Bootstrap, mnt, "-f")
	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })

	return &served{root: mnt, stop: func() {
		mount.Unmount(mnt)
		d.Stop()
	}}
}

type v2Image struct {
	nydusd, bootstrap, blobDir string
}

func buildV2Image(t testing.TB, work, src string) *v2Image {
	t.Helper()
	nydusd, builder := os.Getenv("NYDUS_E2E_BENCH_V2_NYDUSD"), os.Getenv("NYDUS_E2E_BENCH_V2_IMAGE_BIN")
	if nydusd == "" || builder == "" {
		return nil
	}

	t.Log("Building the nydus v2 (rafs v6) image...")

	img := &v2Image{
		nydusd:    nydusd,
		bootstrap: filepath.Join(work, "v2.boot"),
		blobDir:   filepath.Join(work, "v2-blobs"),
	}

	if !assert.NoError(t, os.MkdirAll(img.blobDir, 0o755)) {
		t.FailNow()
	}

	env.Run(t, builder, "create",
		"--fs-version", "6", "--compressor", "zstd",
		"--blob-id", "v2blob",
		"--blob", filepath.Join(img.blobDir, "v2blob"),
		"--external-blob", filepath.Join(work, "v2.ext"),
		"--bootstrap", img.bootstrap,
		src)

	return img
}

func (img *v2Image) startV2Fuse(t testing.TB) *served {
	t.Helper()
	dir := env.WorkDir(t)
	mnt := filepath.Join(dir, "mnt")

	cache := filepath.Join(dir, "cache")
	for _, d := range []string{mnt, cache} {
		if !assert.NoError(t, os.MkdirAll(d, 0o755)) {
			t.FailNow()
		}
	}

	config := filepath.Join(dir, "v2.json")
	if !assert.NoError(t, os.WriteFile(config, fmt.Appendf(nil, `{
  "device": {
    "backend": { "type": "localfs", "config": { "dir": %q } },
    "cache": { "type": "blobcache", "config": { "work_dir": %q } }
  },
  "mode": "direct",
  "digest_validate": false,
  "enable_xattr": true,
  "iostats_files": false
}`, img.blobDir, cache), 0o644)) {
		t.FailNow()
	}

	d := mount.StartDaemon(t, dir, "nydusd-v2", img.nydusd,
		"--config", config,
		"--bootstrap", img.bootstrap,
		"--mountpoint", mnt,
		"--log-level", "error",
	)

	d.WaitFor(t, mountTimeout, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })

	return &served{root: mnt, cache: cache, stop: func() {
		d.Stop()
		mount.Unmount(mnt)
	}}
}
