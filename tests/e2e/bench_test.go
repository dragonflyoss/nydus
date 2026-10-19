package e2e

// Unified cold-start performance benchmark: `nydus fuse`, `nydus nbd`,
// `nydus ublk`, and `nydus fanotify` (plus an optional C erofsfuse column)
// all serve the SAME locally built image (bootstrap + blob dir, prefetch
// disabled, separate cache dirs), so the comparison isolates the read
// transport:
//
//	FUSE:      page-cache miss -> FUSE request -> daemon chunk group map check +
//	           pread cache file -> FUSE reply. Every metadata call is a
//	           userspace round trip.
//	NBD:       page-cache miss -> EROFS -> block layer -> NBD socket ->
//	           daemon pread cache file -> reply. Metadata is served by the
//	           kernel EROFS driver.
//	ublk:      like NBD, but block requests go through ublk_drv's io_uring
//	           SQE/CQE shared memory instead of a kernel socket.
//	fanotify:  kernel EROFS mount over the cache files; a FAN_PRE_ACCESS
//	           event fills missing ranges, warm reads never leave the
//	           kernel (Linux >= 6.15).
//	fileio:    kernel EROFS mounted on a single FUSE-exported file
//	           (CONFIG_EROFS_FS_BACKED_BY_FILE); metadata resolves in-kernel
//	           and only cold byte ranges become FUSE reads.
//	erofsfuse: the C erofsfuse reference implementation reading the blob
//	           directly (no daemon, no cache).
//
// Methodology (per mode): wipe the nydus cache, drop the page cache, start
// the daemon, then take a sequence of measurements in which each one touches
// data or metadata this mode has not touched yet:
//
//	mount ready         daemon up and the tree mountable
//	cold metadata walk  one readdir+lstat pass over the whole tree, taken
//	                    first so nothing has warmed it — the only row a
//	                    bootstrap prewarm can move
//	cold walk + xattr   the same pass with a listxattr per entry; the delta
//	                    is what xattrs cost on first access
//	first 1MiB          first-byte latency on an untouched file
//	cold seq read       one pass over that file, backend fetch included
//	data fetched        bytes pulled from the backend for exactly that file,
//	                    snapshotted before anything else fetches
//	cold rand read      a non-repeating 4K random pass over a second file
//	                    this mode has never opened
//
// Nothing here is a steady-state loop. Container start reads a rootfs once;
// looping over the same inodes for twenty seconds would report the speed of
// whichever cache ended up holding them, which after the first pass is the
// kernel's page cache in every mode — nydus's FUSE mode hands out effectively
// infinite attr/entry timeouts plus FOPEN_CACHE_DIR, so even its warm stat
// and readdir never leave the kernel. Set NYDUS_E2E_BENCH_WARM=1 to append the
// old steady-state fio and metadata rows for regression tracking.
//
// Unavailable modes (missing kernel module, old kernel, feature not compiled
// in) are skipped individually and their column omitted.
//
// Activation: NYDUS_E2E_RUN_BENCH=1 (set by `make test-bench`). Requires root
// and fio; the NBD/ublk modes additionally need their kernel modules and
// EROFS support, fanotify needs Linux >= 6.15 and an ext4 cache dir
// (the Makefile sets TMPDIR).
//
// Tuning knobs (all optional):
//
//	NYDUS_E2E_PERF_LARGE_FILE_COUNT        Number of large files for read benchmarks (default 8).
//	NYDUS_E2E_PERF_LARGE_FILE_SIZE         Size of each large file (default 64MiB).
//	NYDUS_E2E_PERF_MEDIUM_FILE_COUNT       Number of medium files in the corpus (default 256).
//	NYDUS_E2E_PERF_MEDIUM_FILE             Size of each medium file (default 1MiB).
//	NYDUS_E2E_PERF_SMALL_FILE_COUNT        Number of small files for the stat benchmark (default 10000).
//	NYDUS_E2E_PERF_FIO_RUNTIME             Fio benchmark duration in seconds (default 8, after a 2s ramp).
//	NYDUS_E2E_PERF_FIO_SEQ_NUMJOBS         Sequential-read multi-thread job count (default 4).
//	NYDUS_E2E_PERF_FIO_RAND_NUMJOBS        Random-read multi-thread job count (default 4).
//	NYDUS_E2E_PERF_READDIR_DIRS            Number of directories for the readdir corpus (default 128).
//	NYDUS_E2E_PERF_READDIR_FILES_PER_DIR   Files per directory for the readdir corpus (default 256).
//	NYDUS_E2E_PERF_META_SECS               Metadata benchmark duration in seconds (default 3).
//	NYDUS_E2E_PERF_READDIR_META_SECS       Readdir benchmark duration in seconds (default 3).
//	NYDUS_E2E_PERF_READDIR_PASSES_PER_DIR  Repeated os.ReadDir calls per directory per iteration (default 8).
//	NYDUS_E2E_PERF_COLD_RAND_IO_SIZE       Bytes read by the cold random-read pass (default 16MiB).
//	NYDUS_E2E_BENCH_MODES                    Comma-separated mode names to run; others are skipped.
//	NYDUS_E2E_BENCH_WARM                     Also run and print the steady-state fio/metadata rows.
//	NYDUS_E2E_BENCH_FILEIO_NOWARM            Add the fileio-nowarm column (fileio without the FUSE_NOTIFY_STORE prewarm).
//	NYDUS_E2E_BENCH_V2_NYDUSD, NYDUS_E2E_BENCH_V2_IMAGE_BIN  Paths to nydus v2 binaries; both set adds the v2-fuse column.

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Fixed corpus layout produced by corpus.MakePerfCorpus.
const (
	// perfColdReadFile is the large file the first read and the cold
	// sequential read measure.
	perfColdReadFile = "large/file_0.bin"

	// perfColdRandReadFile is the large file the cold random read measures,
	// never opened before that pass.
	perfColdRandReadFile = "large/file_1.bin"

	// perfSmallDir is the directory of small files the stat benchmarks walk.
	perfSmallDir = "small"

	// perfReaddirDir is the directory fan-out the readdir benchmark reads.
	perfReaddirDir = "dirs"

	// perfXattrDir is the xattr-bearing tree the xattr benchmarks read.
	perfXattrDir = "xattrs"

	// perfXattrName is the xattr every file under perfXattrDir carries.
	perfXattrName = "user.bench"
)

// benchEnv holds the shared image and per-run paths.
type benchEnv struct {
	// fioBin is the fio binary the read benchmarks drive.
	fioBin string

	// workDir is the root of every per-run path.
	workDir string

	// blobDir holds the blobs of the built image.
	blobDir string

	// bootstrap is the bootstrap of the built image.
	bootstrap string

	// fullBlob is the full blob the build writes, for erofsfuse --device.
	fullBlob string

	// nbdDevice is the free /dev/nbdX picked for the NBD mode.
	nbdDevice string

	// v2Nydusd is the nydus v2 daemon from NYDUS_E2E_BENCH_V2_NYDUSD; together
	// with v2ImageBin it enables the optional rafs v6 comparison column.
	v2Nydusd string

	// v2ImageBin is the nydus v2 image builder from
	// NYDUS_E2E_BENCH_V2_IMAGE_BIN.
	v2ImageBin string

	// v2Bootstrap is the bootstrap of the v2 image built from the same
	// corpus.
	v2Bootstrap string

	// v2BlobDir holds the blob of the v2 image.
	v2BlobDir string
}

// servingMode is one serving mode: how to detect availability and how to
// mount and unmount it. All other steps are identical across modes.
type servingMode struct {
	// name is the column header.
	name string

	// skipReason says why the mode is unavailable; the column is omitted when
	// it is not empty.
	skipReason string

	// mountpoint is where the measurements read the image.
	mountpoint string

	// cacheDir is the nydus cache dir, empty when the mode has none
	// (erofsfuse).
	cacheDir string

	// start mounts the mode and returns the function that stops it.
	start func(t *testing.T, mode *servingMode) func()
}

// modeResult collects every measurement for one mode.
type modeResult struct {
	// mountSec is the time from daemon start to a mountable tree.
	mountSec float64

	// coldWalkSec is the duration of the cold readdir+lstat pass.
	coldWalkSec float64

	// coldWalkEntries is how many entries the cold walk visited.
	coldWalkEntries int

	// coldXattrWalkSec is the duration of the cold walk with a listxattr per
	// entry, on a fresh mount.
	coldXattrWalkSec float64

	// negativeLookupRate is the rate of lstat calls on missing names.
	negativeLookupRate float64

	// firstReadSec is the latency of the first 1MiB read of an untouched
	// file.
	firstReadSec float64

	// coldSeqMiBps is the throughput of one cold pass over that file.
	coldSeqMiBps float64

	// coldSeqPageCacheMiB is the page cache growth across the cold read.
	coldSeqPageCacheMiB float64

	// fetchedMiB is the data pulled from the backend for that file, below
	// zero when the mode has no cache.
	fetchedMiB float64

	// coldRandIOPS is the rate of the cold 4K random read pass.
	coldRandIOPS float64

	// coldRandLatencyUs is the mean latency of the cold 4K random read pass.
	coldRandLatencyUs float64

	// warm holds the steady-state rows, nil unless NYDUS_E2E_BENCH_WARM is set.
	warm map[string]*jobResult
}

// TestBench runs the cold-start comparison across every serving mode this
// host supports and prints the table.
func TestBench(t *testing.T) {
	if os.Getenv("NYDUS_E2E_RUN_BENCH") == "" {
		t.Skip("set NYDUS_E2E_RUN_BENCH=1 to enable")
	}
	util.SkipUnlessRoot(t, "mounting FUSE and dropping caches")
	assert := assert.New(t)
	fioBin, err := exec.LookPath("fio")
	if !assert.NoError(err, "fio not found; install with: apt-get install fio") {
		t.FailNow()
	}

	// Build the image every mode serves.
	workDir := t.TempDir()
	e := &benchEnv{
		fioBin:    fioBin,
		workDir:   workDir,
		blobDir:   filepath.Join(workDir, "blobs"),
		bootstrap: filepath.Join(workDir, "image.boot"),
	}
	corpusDir := filepath.Join(workDir, "corpus")
	t.Log("generating performance corpus")
	corpus.MakePerfCorpus(t, corpusDir)
	t.Log("building nydus image (chunk size 1MiB)")
	e.fullBlob = util.BuildImage(t, nydusBin, e.bootstrap, e.blobDir, corpusDir, 1024*1024)

	// Build the nydus v2 image when both v2 binaries are given.
	e.v2Nydusd = os.Getenv("NYDUS_E2E_BENCH_V2_NYDUSD")
	e.v2ImageBin = os.Getenv("NYDUS_E2E_BENCH_V2_IMAGE_BIN")
	if e.v2Nydusd != "" && e.v2ImageBin != "" {
		t.Log("building nydus v2 (rafs v6) image")
		e.v2BlobDir = filepath.Join(e.workDir, "v2-blobs")
		e.v2Bootstrap = filepath.Join(e.workDir, "v2.boot")
		assert.NoError(os.MkdirAll(e.v2BlobDir, 0o755))
		out, err := exec.Command(e.v2ImageBin, "create",
			"--fs-version", "6", "--compressor", "zstd",
			"--blob-id", "v2blob",
			"--blob", filepath.Join(e.v2BlobDir, "v2blob"),
			"--external-blob", filepath.Join(e.workDir, "v2.ext"),
			"--bootstrap", e.v2Bootstrap,
			corpusDir).CombinedOutput()
		assert.NoError(err, "nydus-image create failed: %s", out)
	}

	// NYDUS_E2E_BENCH_MODES=fileio,fileio-buffered runs just those columns:
	// full runs cost minutes per mode, so comparing two variants should not
	// pay for the other five.
	modes := e.newServingModes(t)
	if filter := os.Getenv("NYDUS_E2E_BENCH_MODES"); filter != "" {
		wanted := make(map[string]bool)
		for _, name := range strings.Split(filter, ",") {
			wanted[strings.TrimSpace(name)] = true
		}

		for _, mode := range modes {
			if mode.skipReason == "" && !wanted[mode.name] {
				mode.skipReason = "filtered out by NYDUS_E2E_BENCH_MODES"
			}
		}
	}

	// Measure every available mode.
	results := make(map[string]*modeResult, len(modes))
	for _, mode := range modes {
		if mode.skipReason != "" {
			t.Logf("=== %s: SKIPPED (%s) ===", mode.name, mode.skipReason)
			continue
		}

		t.Logf("=== %s ===", mode.name)
		results[mode.name] = e.measureMode(t, mode)
	}

	assert.NotEmpty(results, "no serving mode is available on this host")
	printResults(t, modes, results)
}

// measureMode measures one mode end to end. Every measurement below touches
// data or metadata this mode has not touched yet, with the page cache dropped
// beforehand, because first access is what decides container start time.
func (e *benchEnv) measureMode(t *testing.T, mode *servingMode) *modeResult {
	t.Helper()
	if mode.cacheDir != "" {
		util.WipeCache(mode.cacheDir)
	}
	util.DropCaches(t)

	result := &modeResult{fetchedMiB: -1}
	func() {
		mountStart := time.Now()
		stop := mode.start(t, mode)
		defer stop()
		result.mountSec = time.Since(mountStart).Seconds()
		t.Logf("  mount ready: %.2fs", result.mountSec)

		// Walk first, before anything else touches the tree: this is the
		// only measurement a bootstrap prewarm can move.
		result.coldWalkSec, result.coldWalkEntries = coldMetadataWalk(t, mode.mountpoint, false)
		t.Logf("  cold metadata walk: %d entries in %.3fs (%.0f entries/s)",
			result.coldWalkEntries, result.coldWalkSec, float64(result.coldWalkEntries)/result.coldWalkSec)

		// Probe missing names the way module resolution does.
		result.negativeLookupRate = benchNegativeLookup(t, filepath.Join(mode.mountpoint, perfSmallDir))
		t.Logf("  negative lookups: %.0f ops/s", result.negativeLookupRate)

		// Time the first byte of an untouched file.
		util.DropCaches(t)
		coldReadFile := filepath.Join(mode.mountpoint, perfColdReadFile)
		readStart := time.Now()
		_, err := util.ReadRange(coldReadFile, 0, 1<<20)
		assert.NoError(t, err, "first cold read failed")
		result.firstReadSec = time.Since(readStart).Seconds()
		t.Logf("  first 1MiB cold read: %.3fs", result.firstReadSec)

		// Single cold pass over a file nothing has read: the end-to-end
		// on-demand fetch path, backend included.
		pageCacheBefore := util.PageCacheMiB(t)
		seqStart := time.Now()
		n := util.ReadWhole(t, coldReadFile)
		result.coldSeqMiBps = float64(n) / (1 << 20) / time.Since(seqStart).Seconds()
		result.coldSeqPageCacheMiB = util.PageCacheMiB(t) - pageCacheBefore
		t.Logf("  cold seq read: %.1f MiB at %.1f MiB/s, page cache +%.1f MiB",
			float64(n)/(1<<20), result.coldSeqMiBps, result.coldSeqPageCacheMiB)

		// Snapshot here, while the only data ever fetched is that one file:
		// anything measured later would fold its fetches into the number.
		// Sum the nydus_read_backend_traffic series of the daemon's metrics
		// endpoint where available (v3 daemons): bytes actually pulled from
		// the backend, as opposed to cache-file disk allocation, which a
		// 4 KiB block per tiny record inflates (a decoded chunk group
		// publishes its records at block-aligned logical offsets, so `du`
		// reports about 3x the real transfer on this corpus).
		if metrics, err := util.TryFetchMetrics(e.apiSocket(mode.name)); err == nil {
			result.fetchedMiB = util.SumMetric(metrics, "nydus_read_backend_traffic") / (1 << 20)
			t.Logf("  backend bytes for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), result.fetchedMiB)
		} else if mode.cacheDir != "" {
			cacheFiles, _ := filepath.Glob(filepath.Join(mode.cacheDir, "*.blob.data"))
			for _, cacheFile := range cacheFiles {
				result.fetchedMiB += float64(util.AllocatedBytes(t, cacheFile)) / (1 << 20)
			}
			t.Logf("  cache allocation for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), result.fetchedMiB)
		}

		// Random 4K reads over a second file this mode has never opened.
		util.DropCaches(t)
		result.coldRandIOPS, result.coldRandLatencyUs = coldRandRead(t, e.fioBin, filepath.Join(mode.mountpoint, perfColdRandReadFile))
		t.Logf("  cold rand read 4K: %.0f IOPS, %.0f µs", result.coldRandIOPS, result.coldRandLatencyUs)

		// Append the steady-state rows on request.
		if os.Getenv("NYDUS_E2E_BENCH_WARM") != "" {
			statDir := filepath.Join(mode.mountpoint, perfSmallDir)
			result.warm = runWarmBenchmarks(t, e.fioBin, coldReadFile, statDir, filepath.Join(mode.mountpoint, perfReaddirDir))
			util.DropCaches(t)
			addMetaBenchmarks(t, result.warm, filepath.Join(mode.mountpoint, perfXattrDir), perfXattrName, statDir)
		}
	}()

	// The xattr pass needs its own mount to be comparable with the plain
	// walk above: a second walk inside one session finds the daemon's own
	// mappings already built, and dropping caches cannot evict those.
	if mode.cacheDir != "" {
		util.WipeCache(mode.cacheDir)
	}
	util.DropCaches(t)
	func() {
		stop := mode.start(t, mode)
		defer stop()
		result.coldXattrWalkSec, _ = coldMetadataWalk(t, mode.mountpoint, true)
		t.Logf("  cold walk + xattr: %.3fs (xattr delta %+.3fs)",
			result.coldXattrWalkSec, result.coldXattrWalkSec-result.coldWalkSec)
	}()

	return result
}

// coldMetadataWalk enumerates the whole mount once with the page cache cold:
// readdir every directory and lstat every entry, optionally adding a
// listxattr per entry. It returns the elapsed seconds and the entry count.
//
// Container start enumerates a rootfs once; it does not stat the same inode a
// million times. A steady-state loop would instead report whichever cache
// ended up holding the metadata, which for every mode here is the kernel's
// — nydus's FUSE mode hands out effectively infinite attr/entry timeouts and
// FOPEN_CACHE_DIR, so its warm stat and readdir are in-kernel too.
func coldMetadataWalk(t *testing.T, mountpoint string, withXattr bool) (float64, int) {
	t.Helper()
	entries := 0
	buf := make([]byte, 4096)

	start := time.Now()
	err := filepath.WalkDir(mountpoint, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// WalkDir fills DirEntry from getdents alone; Info forces the lstat.
		if _, err := d.Info(); err != nil {
			return err
		}
		if withXattr {
			_, _ = unix.Llistxattr(path, buf)
		}
		entries++

		return nil
	})
	elapsed := time.Since(start).Seconds()

	assert.NoError(t, err)
	assert.Greater(t, entries, 1, "%s holds nothing but its root", mountpoint)

	return elapsed, entries
}

// benchNegativeLookup stats the same set of names that do not exist, over and
// over, for one second, and returns the rate. This is what module resolution
// does to a rootfs — Node's require walk and Python's sys.path scan probe far
// more missing paths than existing ones, and they retry the same misses on
// every import. A filesystem that caches negative dentries answers repeats
// from the dcache; one that does not pays a round trip per probe, forever.
func benchNegativeLookup(t *testing.T, dir string) float64 {
	t.Helper()
	names := make([]string, 64)
	for i := range names {
		names[i] = filepath.Join(dir, fmt.Sprintf("no_such_module_%d.js", i))
	}

	ops := 0
	start := time.Now()
	deadline := start.Add(time.Second)
	for time.Now().Before(deadline) {
		for _, name := range names {
			if _, err := os.Lstat(name); err == nil {
				t.Fatalf("%s unexpectedly exists", name)
			}
		}
		ops += len(names)
	}

	return float64(ops) / time.Since(start).Seconds()
}

// coldRandRead does a single non-repeating pass of random 4K reads over a
// file this mode has never touched, so every I/O is an on-demand fetch, and
// returns the IOPS and mean latency. fio's random map keeps blocks from
// repeating, which keeps the page cache out of the measurement.
func coldRandRead(t *testing.T, fioBin, file string) (float64, float64) {
	t.Helper()
	assert.FileExists(t, file)
	ioSize := corpus.EnvInt("NYDUS_E2E_PERF_COLD_RAND_IO_SIZE", 16*1024*1024)
	result := runFio(t, fioBin, []string{
		"--name=cold_rand", "--filename=" + file,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		"--io_size=" + strconv.Itoa(ioSize),
		"--numjobs=1", "--readonly",
	})

	return result.ReadIOPS, result.ReadLatency
}

// newServingModes prepares the per-mode dirs and configs and probes availability.
// A mode that cannot run on this host gets a skip reason instead of failing
// the whole benchmark.
func (e *benchEnv) newServingModes(t *testing.T) []*servingMode {
	t.Helper()
	missingSubcommand := func(subcommand string) string {
		out, err := exec.Command(nydusBin, subcommand, "--help").CombinedOutput()
		if err != nil {
			firstLine, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
			return fmt.Sprintf("nydus binary lacks the %s subcommand (build with --features cli,%s): %s", subcommand, subcommand, firstLine)
		}

		return ""
	}

	// Every nydus mode gets its own mountpoint, cache dir and local-backend
	// config. Prefetch stays disabled: a background prefetch would warm the
	// cache mid-run and corrupt the cold measurements.
	newMode := func(name string, start func(t *testing.T, mode *servingMode) func()) *servingMode {
		mode := &servingMode{
			name:       name,
			mountpoint: filepath.Join(e.workDir, name+"-mnt"),
			cacheDir:   filepath.Join(e.workDir, name+"-cache"),
			start:      start,
		}
		assert.NoError(t, os.MkdirAll(mode.mountpoint, 0o755))
		assert.NoError(t, os.MkdirAll(mode.cacheDir, 0o755))
		util.WriteLocalBackendConfig(t, e.configPath(name), e.blobDir, mode.cacheDir, "none")

		return mode
	}

	fuse := newMode("fuse", e.startFuse)
	fuse.skipReason = missingSubcommand("fuse")

	nbd := newMode("nbd", e.startNbd)
	if nbd.skipReason = missingSubcommand("nbd"); nbd.skipReason == "" {
		if !util.ErofsSupported() {
			nbd.skipReason = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if device, err := util.FindFreeNbdDevice(); err != nil {
			nbd.skipReason = fmt.Sprintf("no free NBD device: %v (try: modprobe nbd)", err)
		} else {
			e.nbdDevice = device
		}
	}

	ublk := newMode("ublk", e.startUblk)
	if ublk.skipReason = missingSubcommand("ublk"); ublk.skipReason == "" {
		if !util.ErofsSupported() {
			ublk.skipReason = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if exec.Command("modprobe", "ublk_drv").Run() != nil {
			ublk.skipReason = "ublk_drv unavailable (needs Linux 6.0+; try: modprobe ublk_drv)"
		} else if _, err := os.Stat("/dev/ublk-control"); err != nil {
			ublk.skipReason = fmt.Sprintf("/dev/ublk-control is missing: %v", err)
		}
	}

	fanotify := newMode("fanotify", e.startFanotify)
	if fanotify.skipReason = missingSubcommand("fanotify"); fanotify.skipReason == "" {
		if major, minor := util.KernelVersion(t); major < 6 || (major == 6 && minor < 15) {
			fanotify.skipReason = fmt.Sprintf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", major, minor)
		}
	}

	fileio := newMode("fileio", func(t *testing.T, mode *servingMode) func() { return e.startFileio(t, mode, true, true) })
	if fileio.skipReason = missingSubcommand("fileio"); fileio.skipReason == "" {
		if !util.ErofsSupported() {
			fileio.skipReason = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if major, minor := util.KernelVersion(t); major < 6 || (major == 6 && minor < 12) {
			fileio.skipReason = fmt.Sprintf("kernel %d.%d < 6.12: CONFIG_EROFS_FS_BACKED_BY_FILE unavailable", major, minor)
		}
	}

	// Same serving path with the bootstrap prewarm off: the delta against the
	// fileio column is what FUSE_NOTIFY_STORE is worth.
	fileioNoWarm := newMode("fileio-nowarm", func(t *testing.T, mode *servingMode) func() { return e.startFileio(t, mode, false, true) })
	if fileioNoWarm.skipReason = fileio.skipReason; fileioNoWarm.skipReason == "" && os.Getenv("NYDUS_E2E_BENCH_FILEIO_NOWARM") == "" {
		fileioNoWarm.skipReason = "set NYDUS_E2E_BENCH_FILEIO_NOWARM=1 to enable the fileio-nowarm column"
	}

	// Same serving path without EROFS 'directio' (the daemon's default is
	// on): the delta against the fileio column is what holding the image in
	// the export's page cache as well buys and costs.
	fileioBuffered := newMode("fileio-buffered", func(t *testing.T, mode *servingMode) func() { return e.startFileio(t, mode, true, false) })
	fileioBuffered.skipReason = fileio.skipReason

	// The reference reader has no daemon and no cache.
	erofsfuse := &servingMode{
		name:       "erofsfuse",
		mountpoint: filepath.Join(e.workDir, "erofsfuse-mnt"),
		start:      e.startErofsfuse,
	}
	assert.NoError(t, os.MkdirAll(erofsfuse.mountpoint, 0o755))
	if _, err := util.LookupErofsFuse(); err != nil {
		erofsfuse.skipReason = err.Error()
	}

	v2Fuse := &servingMode{
		name:       "v2-fuse",
		mountpoint: filepath.Join(e.workDir, "v2-mnt"),
		cacheDir:   filepath.Join(e.workDir, "v2-cache"),
		start:      e.startV2Fuse,
	}
	assert.NoError(t, os.MkdirAll(v2Fuse.mountpoint, 0o755))
	assert.NoError(t, os.MkdirAll(v2Fuse.cacheDir, 0o755))
	if e.v2Bootstrap == "" {
		v2Fuse.skipReason = "set NYDUS_E2E_BENCH_V2_NYDUSD and NYDUS_E2E_BENCH_V2_IMAGE_BIN to enable the v2 column"
	}

	return []*servingMode{v2Fuse, fuse, nbd, ublk, fanotify, fileio, fileioNoWarm, fileioBuffered, erofsfuse}
}

// configPath returns the storage config of mode name.
func (e *benchEnv) configPath(name string) string {
	return filepath.Join(e.workDir, name+".yaml")
}

// apiSocket returns the Unix socket mode name's daemon serves Prometheus
// /metrics on.
func (e *benchEnv) apiSocket(name string) string {
	return filepath.Join(e.workDir, name+"-api.sock")
}

// consoleLog returns the console log of mode name's daemon.
func (e *benchEnv) consoleLog(name string) string {
	return filepath.Join(e.workDir, name+".log")
}

// logDir returns the log directory of mode name's daemon, creating it.
func (e *benchEnv) logDir(name string) string {
	dir := filepath.Join(e.workDir, name+"-logs")
	_ = os.MkdirAll(dir, 0o755)

	return dir
}

// startV2Fuse serves the v2 image with the nydus v2 daemon and returns the
// function that stops it.
func (e *benchEnv) startV2Fuse(t *testing.T, mode *servingMode) func() {
	t.Helper()
	config := fmt.Sprintf(`{
  "device": {
    "backend": { "type": "localfs", "config": { "dir": %q } },
    "cache": { "type": "blobcache", "config": { "work_dir": %q } }
  },
  "mode": "direct",
  "digest_validate": false,
  "enable_xattr": true,
  "iostats_files": false
}`, e.v2BlobDir, mode.cacheDir)
	configPath := filepath.Join(e.workDir, "v2.json")
	assert.NoError(t, os.WriteFile(configPath, []byte(config), 0o644))

	d := &util.Daemon{ConsoleLog: e.consoleLog("v2-fuse")}
	d.Start(t, exec.Command(e.v2Nydusd,
		"--config", configPath,
		"--bootstrap", e.v2Bootstrap,
		"--mountpoint", mode.mountpoint,
		"--log-level", "error",
	))
	stop := func() {
		d.Stop()
		util.Unmount(mode.mountpoint)
	}
	t.Cleanup(stop)
	d.WaitReady(t, func() bool { return util.IsMountpoint(mode.mountpoint) })

	return stop
}

// startFuse serves the image with `nydus fuse` and returns the function that
// stops it.
func (e *benchEnv) startFuse(t *testing.T, mode *servingMode) func() {
	t.Helper()
	return e.startDaemon(t, mode, exec.Command(nydusBin, "fuse",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("fuse"),
		"--mountpoint", mode.mountpoint,
		"--apiserver", "unix://"+e.apiSocket("fuse"),
	), nil, nil)
}

// startDaemon starts a nydus daemon that mounts mode.mountpoint, registers
// its stop, which stops the daemon, unmounts and then runs after, and waits
// for the mount and for ready when one is given.
func (e *benchEnv) startDaemon(t *testing.T, mode *servingMode, cmd *exec.Cmd, ready func(d *util.Daemon) bool, after func()) func() {
	t.Helper()
	d := &util.Daemon{ConsoleLog: e.consoleLog(mode.name), LogDir: e.logDir(mode.name)}
	d.Start(t, cmd)
	stop := func() {
		d.Stop()
		util.Unmount(mode.mountpoint)
		if after != nil {
			after()
		}
	}
	t.Cleanup(stop)
	d.WaitReady(t, func() bool {
		return util.IsMountpoint(mode.mountpoint) && (ready == nil || ready(d))
	})

	return stop
}

// startNbd serves the image with `nydus nbd` on the picked device and
// returns the function that stops it.
func (e *benchEnv) startNbd(t *testing.T, mode *servingMode) func() {
	t.Helper()
	return e.startDaemon(t, mode, exec.Command(nydusBin, "nbd",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("nbd"),
		"--device", e.nbdDevice,
		"--mountpoint", mode.mountpoint,
		"--log-level", "info",
		"--log-dir", e.logDir("nbd"),
	), nil, func() { util.WaitNbdDetached(t, e.nbdDevice) })
}

// startUblk serves the image with `nydus ublk`, mounts the block device it
// reports with the kernel EROFS driver and returns the function that stops
// it.
func (e *benchEnv) startUblk(t *testing.T, mode *servingMode) func() {
	t.Helper()
	d := &util.Daemon{ConsoleLog: e.consoleLog("ublk"), LogDir: e.logDir("ublk")}
	d.Start(t, exec.Command(nydusBin, "ublk",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("ublk"),
		"--log-level", "info",
		"--log-dir", e.logDir("ublk"),
		"--apiserver", "unix://"+e.apiSocket("ublk"),
	))

	// Unmount before stopping the daemon: it serves I/O for its own block
	// device, so unmounting while it exits would deadlock.
	stop := func() {
		util.Unmount(mode.mountpoint)
		d.Stop()
	}
	t.Cleanup(stop)

	// The daemon prints the /dev/ublkbN path on stdout once ready.
	var devicePath string
	d.WaitReady(t, func() bool {
		for _, line := range strings.Split(d.Logs(), "\n") {
			if line = strings.TrimSpace(line); strings.HasPrefix(line, "/dev/ublkb") {
				devicePath = line
				return true
			}
		}

		return false
	})
	assert.Eventually(t, func() bool {
		_, err := os.Stat(devicePath)
		return err == nil
	}, 10*time.Second, 200*time.Millisecond, "%s did not appear", devicePath)

	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", devicePath, mode.mountpoint).CombinedOutput()
	if !assert.NoError(t, err, "failed to mount %s as erofs: %s", devicePath, out) {
		t.FailNow()
	}

	return stop
}

// startFanotify serves the image with `nydus fanotify` and returns the
// function that stops it.
func (e *benchEnv) startFanotify(t *testing.T, mode *servingMode) func() {
	t.Helper()

	// The mount appears before the event loop serves it, so wait for both.
	return e.startDaemon(t, mode, exec.Command(nydusBin, "fanotify",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("fanotify"),
		"--mountpoint", mode.mountpoint,
		"--log-level", "info",
		"--log-dir", e.logDir("fanotify"),
	), func(d *util.Daemon) bool { return strings.Contains(d.Logs(), "event loop ready") }, nil)
}

// startFileio exports the flattened image over FUSE and lets the kernel EROFS
// driver mount that file directly, so the daemon owns both mounts and tears
// them down in dependency order on shutdown. warmBootstrap pushes the
// bootstrap into the kernel with FUSE_NOTIFY_STORE and directIO mounts EROFS
// with 'directio'. It returns the function that stops the daemon.
func (e *benchEnv) startFileio(t *testing.T, mode *servingMode, warmBootstrap, directIO bool) func() {
	t.Helper()
	exportDir := filepath.Join(e.workDir, mode.name+"-export")
	assert.NoError(t, os.MkdirAll(exportDir, 0o755))

	// The daemon unmounts EROFS before ending the export; the fallback
	// unmount only matters if it died without running its shutdown path.
	return e.startDaemon(t, mode, exec.Command(nydusBin, "fileio",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath(mode.name),
		"--export-dir", exportDir,
		"--mountpoint", mode.mountpoint,
		"--warm-bootstrap", strconv.FormatBool(warmBootstrap),
		"--direct-io", strconv.FormatBool(directIO),
		"--log-level", "info",
		"--log-dir", e.logDir(mode.name),
		"--apiserver", "unix://"+e.apiSocket(mode.name),
	), nil, func() { util.Unmount(exportDir) })
}

// startErofsfuse mounts the image with the C erofsfuse reference reader and
// returns the function that unmounts it.
func (e *benchEnv) startErofsfuse(t *testing.T, mode *servingMode) func() {
	t.Helper()
	erofsfuseBin, err := util.LookupErofsFuse()
	assert.NoError(t, err)

	return util.MountErofsFuse(t, erofsfuseBin, e.bootstrap, mode.mountpoint, e.fullBlob)
}

// printResults logs one column per measured mode, the steady-state rows
// under NYDUS_E2E_BENCH_WARM, and the skipped modes with their reasons.
func printResults(t *testing.T, modes []*servingMode, results map[string]*modeResult) {
	// One column per mode that produced a result.
	var measured []*servingMode
	for _, mode := range modes {
		if results[mode.name] != nil {
			measured = append(measured, mode)
		}
	}

	// Build the table header.
	writer := table.NewWriter()
	writer.SetStyle(table.StyleLight)
	writer.Style().Options.SeparateRows = false
	header := table.Row{"Benchmark"}
	columns := []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}}
	for i, mode := range measured {
		header = append(header, mode.name)
		columns = append(columns, table.ColumnConfig{Number: 2 + i, Align: text.AlignRight})
	}
	writer.AppendHeader(header)
	writer.SetColumnConfigs(columns)

	appendRow := func(label string, cell func(result *modeResult) string) {
		cells := table.Row{label}
		for _, mode := range measured {
			cells = append(cells, cell(results[mode.name]))
		}
		writer.AppendRow(cells)
	}

	// Cold-start rows.
	appendRow("Mount ready", func(result *modeResult) string {
		return fmt.Sprintf("%.2f s", result.mountSec)
	})
	appendRow("Cold metadata walk", func(result *modeResult) string {
		return fmt.Sprintf("%.3f s", result.coldWalkSec)
	})
	appendRow("Cold walk rate", func(result *modeResult) string {
		if result.coldWalkSec <= 0 {
			return "—"
		}
		return fmt.Sprintf("%.0f ent/s", float64(result.coldWalkEntries)/result.coldWalkSec)
	})
	appendRow("Cold walk + xattr", func(result *modeResult) string {
		return fmt.Sprintf("%.3f s", result.coldXattrWalkSec)
	})
	appendRow("  xattr delta", func(result *modeResult) string {
		return fmt.Sprintf("%+.3f s", result.coldXattrWalkSec-result.coldWalkSec)
	})
	appendRow("Negative lookup ops/s", func(result *modeResult) string {
		return fmt.Sprintf("%.0f op/s", result.negativeLookupRate)
	})
	appendRow("First 1MiB cold read", func(result *modeResult) string {
		return fmt.Sprintf("%.3f s", result.firstReadSec)
	})
	appendRow("Cold seq read (64MiB)", func(result *modeResult) string {
		return fmt.Sprintf("%.1f MiB/s", result.coldSeqMiBps)
	})
	appendRow("  page cache used", func(result *modeResult) string {
		return fmt.Sprintf("%.1f MiB", result.coldSeqPageCacheMiB)
	})
	appendRow("Backend read (that 64MiB)", func(result *modeResult) string {
		if result.fetchedMiB < 0 {
			return "—"
		}
		return fmt.Sprintf("%.1f MiB", result.fetchedMiB)
	})
	appendRow("Cold rand read IOPS (4K)", func(result *modeResult) string {
		return fmt.Sprintf("%.0f IOPS", result.coldRandIOPS)
	})
	appendRow("Cold rand read Lat (4K)", func(result *modeResult) string {
		return fmt.Sprintf("%.0f µs", result.coldRandLatencyUs)
	})

	// Steady-state rows: only populated under NYDUS_E2E_BENCH_WARM. They say
	// little about container start, and once every mode's metadata is in the
	// kernel's caches they largely measure the same page-cache path.
	if os.Getenv("NYDUS_E2E_BENCH_WARM") != "" {
		type warmRow struct {
			label string
			key   string
			unit  string
			value func(job *jobResult) float64
		}
		bandwidth := func(job *jobResult) float64 { return job.ReadBW }
		iops := func(job *jobResult) float64 { return job.ReadIOPS }
		latency := func(job *jobResult) float64 { return job.ReadLatency }
		warmRows := []warmRow{
			{"Seq Read BW (128K)", "seq_read_128k", "MiB/s", bandwidth},
			{"Rand Read BW (128K)", "rand_read_128k", "MiB/s", bandwidth},
			{"Seq Read BW (4K)", "seq_read_4k", "MiB/s", bandwidth},
			{"Rand Read IOPS (4K)", "rand_read_4k", "IOPS", iops},
			{"Rand Read Lat (4K)", "rand_read_4k", "µs", latency},
			{"Seq 4t BW (128K)", "seq_read_4t_128k", "MiB/s", bandwidth},
			{"Rand 4t BW (128K)", "rand_read_4t_128k", "MiB/s", bandwidth},
			{"Seq 4t BW (4K)", "seq_read_4t_4k", "MiB/s", bandwidth},
			{"Rand 4t BW (4K)", "rand_read_4t_4k", "MiB/s", bandwidth},
			{"Stat IOPS", "stat", "IOPS", iops},
			{"Stat Latency", "stat", "µs", latency},
			{"Readdir IOPS", "readdir", "IOPS", iops},
			{"Readdir Latency", "readdir", "µs", latency},
			{"Listxattr IOPS", "listxattr", "IOPS", iops},
			{"Listxattr Latency", "listxattr", "µs", latency},
			{"Getxattr IOPS", "getxattr", "IOPS", iops},
			{"Getxattr Latency", "getxattr", "µs", latency},
			{"Readdir+stat (ls -l) IOPS", "readdir_stat", "IOPS", iops},
			{"Readdir+stat (ls -l) Latency", "readdir_stat", "µs", latency},
		}

		writer.AppendSeparator()
		for _, row := range warmRows {
			appendRow(row.label, func(result *modeResult) string {
				if job, ok := result.warm[row.key]; ok && job != nil {
					return fmt.Sprintf("%.1f %s", row.value(job), row.unit)
				}
				return "—"
			})
		}
	}

	// Name the skipped modes under the table.
	var skipped []string
	for _, mode := range modes {
		if mode.skipReason != "" {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", mode.name, mode.skipReason))
		}
	}
	suffix := ""
	if len(skipped) > 0 {
		suffix = "\nSkipped modes: " + strings.Join(skipped, "; ")
	}

	t.Log("\nCold-start Performance Comparison (local backend, cold page cache)\n" + writer.Render() + suffix)
}

// runWarmBenchmarks executes the full I/O and metadata benchmark suite and
// returns the per-benchmark results keyed by name. The page cache is dropped
// before each fio job to force cache-miss reads. Every job passes
// --invalidate=0: fio's default invalidate=1 fadvises the target file out of
// the page cache at job start, and cache state must be controlled by the
// drop alone.
func runWarmBenchmarks(t *testing.T, fioBin, file, statDir, readdirDir string) map[string]*jobResult {
	assert.FileExists(t, file)
	fioRuntime := corpus.EnvInt("NYDUS_E2E_PERF_FIO_RUNTIME", 8)
	fioSeqNumjobs := corpus.EnvInt("NYDUS_E2E_PERF_FIO_SEQ_NUMJOBS", 4)
	fioRandNumjobs := corpus.EnvInt("NYDUS_E2E_PERF_FIO_RAND_NUMJOBS", 4)
	results := make(map[string]*jobResult)

	// Single-thread read jobs.
	util.DropCaches(t)
	results["seq_read_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read", "--filename=" + file,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})
	util.DropCaches(t)
	results["rand_read_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read", "--filename=" + file,
		"--rw=randread", "--bs=128k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})
	util.DropCaches(t)
	results["seq_read_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4k", "--filename=" + file,
		"--rw=read", "--bs=4k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})
	util.DropCaches(t)
	results["rand_read_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4k", "--filename=" + file,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})

	// Multi-thread read jobs.
	util.DropCaches(t)
	results["seq_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + file,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})
	util.DropCaches(t)
	results["rand_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + file,
		"--rw=randread", "--bs=128k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})
	util.DropCaches(t)
	results["seq_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + file,
		"--rw=read", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})
	util.DropCaches(t)
	results["rand_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + file,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})

	// Metadata jobs.
	util.DropCaches(t)
	results["stat"] = benchStat(t, statDir)
	util.DropCaches(t)
	results["readdir"] = benchReaddir(t, readdirDir)

	return results
}

// addMetaBenchmarks runs the metadata-only benchmarks (listxattr, getxattr,
// readdir+stat) and inserts their results into results.
func addMetaBenchmarks(t *testing.T, results map[string]*jobResult, xattrDir, xattrName, statDir string) {
	t.Helper()
	if xattrDir != "" {
		results["listxattr"] = benchXattr("listxattr", xattrDir, func(file string, buf []byte) { _, _ = unix.Listxattr(file, buf) })
		if xattrName != "" {
			results["getxattr"] = benchXattr("getxattr", xattrDir, func(file string, buf []byte) { _, _ = unix.Getxattr(file, xattrName, buf) })
		}
	}
	results["readdir_stat"] = benchReaddirStat(t, statDir)
}

// benchMetadata runs pass back to back for duration and reports the achieved
// ops/s and latency of a job that does opsPerPass operations per pass.
func benchMetadata(name string, duration time.Duration, opsPerPass int, pass func()) *jobResult {
	iterations := 0
	start := time.Now()
	for deadline := start.Add(duration); time.Now().Before(deadline); iterations++ {
		pass()
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * opsPerPass)

	return &jobResult{
		Name:        name,
		ReadIOPS:    totalOps / elapsed.Seconds(),
		ReadLatency: elapsed.Seconds() / totalOps * 1e6,
	}
}

// metaDuration returns the duration of one metadata benchmark job, from the
// environment variable env in seconds.
func metaDuration(env string) time.Duration {
	return time.Duration(corpus.EnvInt(env, 3)) * time.Second
}

// regularFiles returns every non-directory path under dir.
func regularFiles(dir string) []string {
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}

		return nil
	})

	return files
}

// benchStat stats every file under dir per pass.
func benchStat(t *testing.T, dir string) *jobResult {
	t.Helper()
	files := regularFiles(dir)
	assert.NotEmpty(t, files)

	return benchMetadata("stat", metaDuration("NYDUS_E2E_PERF_META_SECS"), len(files), func() {
		for _, file := range files {
			_, _ = os.Stat(file)
		}
	})
}

// benchReaddir reads every subdirectory of dir several times per pass.
func benchReaddir(t *testing.T, dir string) *jobResult {
	t.Helper()
	passesPerDir := corpus.EnvInt("NYDUS_E2E_PERF_READDIR_PASSES_PER_DIR", 8)
	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)

	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(dir, entry.Name()))
		}
	}
	assert.NotEmpty(t, dirs)

	return benchMetadata("readdir", metaDuration("NYDUS_E2E_PERF_READDIR_META_SECS"), len(dirs)*passesPerDir, func() {
		for _, subdir := range dirs {
			for range passesPerDir {
				_, _ = os.ReadDir(subdir)
			}
		}
	})
}

// benchXattr runs the xattr call op on every file under dir per pass, nil
// when dir holds no files.
func benchXattr(name, dir string, op func(file string, buf []byte)) *jobResult {
	files := regularFiles(dir)
	if len(files) == 0 {
		return nil
	}

	buf := make([]byte, 512)
	return benchMetadata(name, metaDuration("NYDUS_E2E_PERF_META_SECS"), len(files), func() {
		for _, file := range files {
			op(file, buf)
		}
	})
}

// benchReaddirStat lists dir and lstats every entry per pass, the `ls -l`
// workload, nil when dir is empty.
func benchReaddirStat(t *testing.T, dir string) *jobResult {
	t.Helper()
	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)
	if len(entries) == 0 {
		return nil
	}

	return benchMetadata("readdir_stat", metaDuration("NYDUS_E2E_PERF_META_SECS"), 1, func() {
		listed, _ := os.ReadDir(dir)
		for _, entry := range listed {
			_, _ = os.Lstat(filepath.Join(dir, entry.Name()))
		}
	})
}

// jobResult is the per-job summary extracted from a benchmark run.
type jobResult struct {
	// Name is a short name identifying the benchmark, e.g. "seq_read_128k".
	Name string

	// ReadBW is the throughput in MB/s.
	ReadBW float64

	// ReadIOPS is the I/O operations per second.
	ReadIOPS float64

	// ReadLatency is the average latency in microseconds.
	ReadLatency float64
}

// fioJSONResult mirrors the subset of fio's JSON output the benchmark reads.
type fioJSONResult struct {
	// Jobs is one entry per fio job.
	Jobs []struct {
		// Jobname is the --name of the job.
		Jobname string `json:"jobname"`

		// Read is the read-side summary of the job.
		Read struct {
			// Bw is the bandwidth in KB/s.
			Bw float64 `json:"bw"`

			// Iops is the I/O operations per second.
			Iops float64 `json:"iops"`

			// LatNs is the completion latency distribution.
			LatNs struct {
				// Mean is the mean latency in nanoseconds.
				Mean float64 `json:"mean"`
			} `json:"lat_ns"`
		} `json:"read"`
	} `json:"jobs"`
}

// runFio runs a single fio job with JSON output and returns its summary.
func runFio(t *testing.T, fioBin string, args []string) *jobResult {
	out, err := exec.Command(fioBin, append([]string{"--output-format=json"}, args...)...).CombinedOutput()
	assert.NoError(t, err, "fio failed: %s", out)

	var output fioJSONResult
	assert.NoError(t, json.Unmarshal(out, &output))
	if !assert.NotEmpty(t, output.Jobs) {
		return &jobResult{}
	}

	job := output.Jobs[0]

	return &jobResult{
		Name:        job.Jobname,
		ReadBW:      job.Read.Bw / 1024.0,
		ReadIOPS:    job.Read.Iops,
		ReadLatency: job.Read.LatNs.Mean / 1000.0,
	}
}
