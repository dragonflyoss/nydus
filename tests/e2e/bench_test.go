package e2e

// Unified cold-start performance benchmark: `nydus fuse`, `nydus nbd`,
// `nydus ublk`, and `nydus fanotify` (plus an optional C erofsfuse column)
// all serve the SAME locally built image (bootstrap + blob dir, prefetch
// disabled, separate cache dirs), so the comparison isolates the read
// transport:
//
//	FUSE:      page-cache miss -> FUSE request -> daemon block group map check +
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
// and readdir never leave the kernel. Set NYDUSFS_BENCH_WARM=1 to append the
// old steady-state fio and metadata rows for regression tracking.
//
// Unavailable modes (missing kernel module, old kernel, feature not compiled
// in) are skipped individually and their column omitted.
//
// Activation: NYDUSFS_RUN_BENCH=1 (set by `make test-bench`). Requires root
// and fio; the NBD/ublk modes additionally need their kernel modules and
// EROFS support, fanotify needs Linux >= 6.15 and an ext4 cache dir
// (the Makefile sets TMPDIR).
//
// Tuning knobs (all optional):
//
//	NYDUSFS_PERF_LARGE_FILE_COUNT        Number of large files for read benchmarks (default 8).
//	NYDUSFS_PERF_LARGE_FILE_SIZE         Size of each large file (default 64MiB).
//	NYDUSFS_PERF_MEDIUM_FILE_COUNT       Number of medium files in the corpus (default 256).
//	NYDUSFS_PERF_MEDIUM_FILE             Size of each medium file (default 1MiB).
//	NYDUSFS_PERF_SMALL_FILE_COUNT        Number of small files for the stat benchmark (default 10000).
//	NYDUSFS_PERF_FIO_RUNTIME             Fio benchmark duration in seconds (default 8, after a 2s ramp).
//	NYDUSFS_PERF_FIO_SEQ_NUMJOBS         Sequential-read multi-thread job count (default 4).
//	NYDUSFS_PERF_FIO_RAND_NUMJOBS        Random-read multi-thread job count (default 4).
//	NYDUSFS_PERF_READDIR_DIRS            Number of directories for the readdir corpus (default 128).
//	NYDUSFS_PERF_READDIR_FILES_PER_DIR   Files per directory for the readdir corpus (default 256).
//	NYDUSFS_PERF_META_SECS               Metadata benchmark duration in seconds (default 3).
//	NYDUSFS_PERF_READDIR_META_SECS       Readdir benchmark duration in seconds (default 3).
//	NYDUSFS_PERF_READDIR_PASSES_PER_DIR  Repeated os.ReadDir calls per directory per iteration (default 8).
//	NYDUSFS_PERF_COLD_RAND_IO_SIZE       Bytes read by the cold random-read pass (default 16MiB).
//	NYDUSFS_BENCH_MODES                    Comma-separated mode names to run; others are skipped.
//	NYDUSFS_BENCH_WARM                     Also run and print the steady-state fio/metadata rows.
//	NYDUSFS_BENCH_NOCDC_FUSE               Add the fuse-nocdc column (image built with --deduplicator none).
//	NYDUSFS_BENCH_FILEIO_NOWARM            Add the fileio-nowarm column (fileio without the FUSE_NOTIFY_STORE prewarm).
//	NYDUSFS_BENCH_V2_NYDUSD, NYDUSFS_BENCH_V2_IMAGE_BIN  Paths to nydus v2 binaries; both set adds the v2-fuse column.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Fixed corpus layout produced by corpus.MakePerfCorpus.
const (
	benchTargetRel   = "large/file_0.bin"
	benchRandRel     = "large/file_1.bin"
	benchStatRel     = "small"
	benchReaddirRel  = "dirs"
	benchXattrRel    = "xattrs"
	benchXattrName   = "user.bench"
	benchErofsfuse   = "erofsfuse"
	benchStopTimeout = 20 * time.Second
)

// benchEnv holds the shared image and per-run paths.
type benchEnv struct {
	nydusBin string
	fioBin   string

	workDir   string
	blobDir   string
	bootstrap string
	blobPath  string // single blob produced by the build, for erofsfuse --device
	nbdDev    string // free /dev/nbdX picked for the NBD mode

	// Optional fuse-nocdc comparison column (--deduplicator none image),
	// enabled by the NYDUSFS_BENCH_NOCDC_FUSE environment variable.
	nocdcBootstrap string
	nocdcBlobDir   string

	// Optional nydus v2 (rafs v6) comparison column, enabled by the
	// NYDUSFS_BENCH_V2_NYDUSD and NYDUSFS_BENCH_V2_IMAGE_BIN environment variables.
	v2Nydusd    string
	v2ImageBin  string
	v2Bootstrap string
	v2BlobDir   string
}

// benchMode is one serving mode: how to detect availability and how to
// mount/unmount it. All other steps are identical across modes.
type benchMode struct {
	name  string
	skip  string // non-empty: mode unavailable, column omitted
	mnt   string
	cache string // "" when the mode has no nydus cache (erofsfuse)
	start func(t *testing.T) (stop func())
}

// benchModeResult collects every measurement for one mode.
type benchModeResult struct {
	mountSec          float64
	coldWalkSec       float64
	coldWalkEntries   int
	coldXattrWalkSec  float64
	negativeLookupOps float64
	firstReadSec      float64
	coldSeqMiBps      float64
	coldSeqCachedMiB  float64 // page cache growth across the cold read
	fetchedMiB        float64 // < 0 when the mode has no cache
	coldRandIOPS      float64
	coldRandLatUs     float64
	bench             map[string]*benchResult // nil unless NYDUSFS_BENCH_WARM is set
}

// cachedMiB reports the kernel's total page cache from /proc/meminfo.
//
// Serving one byte can cache it more than once: the daemon's own copy of the
// blob cache file, an intermediate object (the FUSE export, a block device),
// and finally the inode the application reads. Growth across a cold read of a
// known size is the cheapest way to see how many of those copies survive.
func cachedMiB(t *testing.T) float64 {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	require.NoError(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Cached:") {
			continue
		}
		var kb float64
		if _, err := fmt.Sscanf(strings.TrimPrefix(line, "Cached:"), "%f kB", &kb); err == nil {
			return kb / 1024
		}
	}
	return -1
}

func TestBench(t *testing.T) {
	if os.Getenv("NYDUSFS_RUN_BENCH") == "" {
		t.Skip("set NYDUSFS_RUN_BENCH=1 to enable")
	}
	if os.Getuid() != 0 {
		t.Fatal("requires root")
	}

	e := &benchEnv{
		fioBin:   mustLookupFio(t),
		nydusBin: mustLookupExecutable(t, "nydus"),
	}
	e.workDir = t.TempDir()
	corpusDir := filepath.Join(e.workDir, "corpus")
	e.blobDir = filepath.Join(e.workDir, "blobs")
	e.bootstrap = filepath.Join(e.workDir, "bootstrap.boot")

	t.Log("Generating performance corpus...")
	corpus.MakePerfCorpus(t, corpusDir)
	t.Log("Building NydusFS image (chunksize=1MiB)...")
	e.blobPath = buildNydusFSImageToDir(t, e.nydusBin, e.bootstrap, e.blobDir, corpusDir, 1024*1024)

	if os.Getenv("NYDUSFS_BENCH_NOCDC_FUSE") != "" {
		t.Log("Building NydusFS image with --deduplicator none...")
		e.nocdcBlobDir = filepath.Join(e.workDir, "nocdc-blobs")
		e.nocdcBootstrap = filepath.Join(e.workDir, "nocdc.boot")
		buildNydusFSImageToDir(t, e.nydusBin, e.nocdcBootstrap, e.nocdcBlobDir, corpusDir, 1024*1024,
			"--deduplicator", "none")
	}

	e.v2Nydusd = os.Getenv("NYDUSFS_BENCH_V2_NYDUSD")
	e.v2ImageBin = os.Getenv("NYDUSFS_BENCH_V2_IMAGE_BIN")
	if e.v2Nydusd != "" && e.v2ImageBin != "" {
		t.Log("Building nydus v2 (rafs v6) image...")
		e.v2BlobDir = filepath.Join(e.workDir, "v2-blobs")
		e.v2Bootstrap = filepath.Join(e.workDir, "v2.boot")
		require.NoError(t, os.MkdirAll(e.v2BlobDir, 0755))
		out, err := exec.Command(e.v2ImageBin, "create",
			"--fs-version", "6", "--compressor", "zstd",
			"--blob-id", "v2blob",
			"--blob", filepath.Join(e.v2BlobDir, "v2blob"),
			"--external-blob", filepath.Join(e.workDir, "v2.ext"),
			"--bootstrap", e.v2Bootstrap,
			corpusDir).CombinedOutput()
		require.NoError(t, err, "nydus-image create failed: %s", string(out))
	}

	modes := e.buildModes(t)
	// NYDUSFS_BENCH_MODES=fileio,fileio-directio runs just those columns —
	// full runs cost minutes per mode, so comparing two variants should not
	// pay for the other five.
	if filter := os.Getenv("NYDUSFS_BENCH_MODES"); filter != "" {
		wanted := make(map[string]bool)
		for _, name := range strings.Split(filter, ",") {
			wanted[strings.TrimSpace(name)] = true
		}
		for _, m := range modes {
			if m.skip == "" && !wanted[m.name] {
				m.skip = "filtered out by NYDUSFS_BENCH_MODES"
			}
		}
	}
	results := make(map[string]*benchModeResult, len(modes))
	for _, m := range modes {
		if m.skip != "" {
			t.Logf("=== %s: SKIPPED (%s) ===", m.name, m.skip)
			continue
		}
		t.Logf("=== %s ===", m.name)
		results[m.name] = e.runMode(t, m)
	}
	require.NotEmpty(t, results, "no serving mode is available on this host")

	printBenchTable(t, modes, results)
}

// runMode measures one mode end to end. Every measurement below touches data
// or metadata this mode has not touched yet, with the page cache dropped
// beforehand, because first access is what decides container start time.
func (e *benchEnv) runMode(t *testing.T, m *benchMode) *benchModeResult {
	t.Helper()
	if m.cache != "" {
		wipeCacheDir(m.cache)
	}
	dropCaches(t)

	res := &benchModeResult{fetchedMiB: -1}
	func() {
		mountStart := time.Now()
		stop := m.start(t)
		defer stop()
		res.mountSec = time.Since(mountStart).Seconds()
		t.Logf("  mount ready: %.2fs", res.mountSec)

		// First, before anything else touches the tree: this is the only
		// measurement a bootstrap prewarm can move.
		res.coldWalkSec, res.coldWalkEntries = coldMetadataWalk(t, m.mnt, false)
		t.Logf("  cold metadata walk: %d entries in %.3fs (%.0f entries/s)",
			res.coldWalkEntries, res.coldWalkSec, float64(res.coldWalkEntries)/res.coldWalkSec)

		res.negativeLookupOps = benchNegativeLookup(t, filepath.Join(m.mnt, benchStatRel))
		t.Logf("  negative lookups: %.0f ops/s", res.negativeLookupOps)

		dropCaches(t)
		target := filepath.Join(m.mnt, benchTargetRel)
		readStart := time.Now()
		_, err := readSlice(target, 0, 1)
		require.NoError(t, err, "first cold read failed")
		res.firstReadSec = time.Since(readStart).Seconds()
		t.Logf("  first 1MiB cold read: %.3fs", res.firstReadSec)

		// Single cold pass over a file nothing has read: the end-to-end
		// on-demand fetch path, backend included.
		cachedBefore := cachedMiB(t)
		seqStart := time.Now()
		n := readWhole(t, target)
		res.coldSeqMiBps = float64(n) / (1 << 20) / time.Since(seqStart).Seconds()
		res.coldSeqCachedMiB = cachedMiB(t) - cachedBefore
		t.Logf("  cold seq read: %.1f MiB at %.1f MiB/s, page cache +%.1f MiB",
			float64(n)/(1<<20), res.coldSeqMiBps, res.coldSeqCachedMiB)

		// Snapshot here, while the only data ever fetched is that one file:
		// anything measured later would fold its fetches into the number.
		// Backend counters from the daemon's metrics endpoint where available
		// (v3 daemons); cache-file disk allocation otherwise.
		if fetched := backendReadMiB(e.apiSocket(m.name)); fetched >= 0 {
			res.fetchedMiB = fetched
			t.Logf("  backend bytes for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), res.fetchedMiB)
		} else if m.cache != "" {
			res.fetchedMiB = cacheDirUsedBytes(m.cache)
			t.Logf("  cache allocation for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), res.fetchedMiB)
		}

		dropCaches(t)
		res.coldRandIOPS, res.coldRandLatUs = coldRandRead(t, e.fioBin, filepath.Join(m.mnt, benchRandRel))
		t.Logf("  cold rand read 4K: %.0f IOPS, %.0f µs", res.coldRandIOPS, res.coldRandLatUs)

		if os.Getenv("NYDUSFS_BENCH_WARM") != "" {
			statDir := filepath.Join(m.mnt, benchStatRel)
			res.bench = runBenchmarks(t, e.fioBin, target, statDir, filepath.Join(m.mnt, benchReaddirRel))
			dropCaches(t)
			addMetaBenchmarks(t, res.bench, filepath.Join(m.mnt, benchXattrRel), benchXattrName, statDir)
		}
	}()

	// The xattr pass needs its own mount to be comparable with the plain
	// walk above: a second walk inside one session finds the daemon's own
	// mappings already built, and dropCaches cannot evict those.
	if m.cache != "" {
		wipeCacheDir(m.cache)
	}
	dropCaches(t)
	func() {
		stop := m.start(t)
		defer stop()
		res.coldXattrWalkSec, _ = coldMetadataWalk(t, m.mnt, true)
		t.Logf("  cold walk + xattr: %.3fs (xattr delta %+.3fs)",
			res.coldXattrWalkSec, res.coldXattrWalkSec-res.coldWalkSec)
	}()
	return res
}

// ------------------------------------------------------------------ modes ----

// coldMetadataWalk enumerates the whole mount once with the page cache cold:
// readdir every directory and lstat every entry, optionally adding a
// listxattr per entry.
//
// Container start enumerates a rootfs once; it does not stat the same inode a
// million times. A steady-state loop would instead report whichever cache
// ended up holding the metadata, which for every mode here is the kernel's
// — nydus's FUSE mode hands out effectively infinite attr/entry timeouts and
// FOPEN_CACHE_DIR, so its warm stat and readdir are in-kernel too.
func coldMetadataWalk(t *testing.T, root string, withXattr bool) (float64, int) {
	t.Helper()
	entries := 0
	buf := make([]byte, 4096)
	start := time.Now()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
	require.NoError(t, err)
	require.NotZero(t, entries)
	return elapsed, entries
}

// benchNegativeLookup stats the same set of names that do not exist, over and
// over, for one second. This is what module resolution does to a rootfs —
// Node's require walk and Python's sys.path scan probe far more missing paths
// than existing ones, and they retry the same misses on every import. A
// filesystem that caches negative dentries answers repeats from the dcache; one
// that does not pays a round trip per probe, forever.
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
// file this mode has never touched, so every I/O is an on-demand fetch.
// fio's random map keeps blocks from repeating, which keeps the page cache
// out of the measurement.
func coldRandRead(t *testing.T, fioBin, file string) (float64, float64) {
	t.Helper()
	require.FileExists(t, file)
	ioSize := corpus.EnvInt("NYDUSFS_PERF_COLD_RAND_IO_SIZE", 16*1024*1024)
	res := runFio(t, fioBin, []string{
		"--name=cold_rand", "--filename=" + file,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--io_size=%d", ioSize),
		"--numjobs=1", "--readonly",
	})
	return res.ReadIOPS, res.ReadLat
}

// buildModes prepares the per-mode dirs/configs and probes availability.
// A mode that cannot run on this host gets a skip reason instead of failing
// the whole benchmark.
func (e *benchEnv) buildModes(t *testing.T) []*benchMode {
	t.Helper()

	subOK := func(sub string) string {
		if out, err := exec.Command(e.nydusBin, sub, "--help").CombinedOutput(); err != nil {
			return fmt.Sprintf("nydus binary lacks the %s subcommand (build with --features cli,%s): %s", sub, sub, firstLine(out))
		}
		return ""
	}
	newMode := func(name string, start func(t *testing.T) func()) *benchMode {
		m := &benchMode{
			name:  name,
			mnt:   filepath.Join(e.workDir, name+"-mnt"),
			cache: filepath.Join(e.workDir, name+"-cache"),
			start: start,
		}
		require.NoError(t, os.MkdirAll(m.mnt, 0755))
		require.NoError(t, os.MkdirAll(m.cache, 0755))
		e.writeConfig(t, name, e.blobDir, m.cache)
		return m
	}

	fuse := newMode("fuse", e.startFuse)
	fuse.skip = subOK("fuse")

	// Same fuse serving path, but the image was built with --deduplicator
	// none (chunkless blob meta): isolates the CDC lookup/dedup cost.
	nocdc := newMode("fuse-nocdc", e.startFuseNocdc)
	if nocdc.skip = subOK("fuse"); nocdc.skip == "" && e.nocdcBootstrap == "" {
		nocdc.skip = "set NYDUSFS_BENCH_NOCDC_FUSE=1 to enable the fuse-nocdc column"
	}
	if nocdc.skip == "" {
		e.writeConfig(t, "fuse-nocdc", e.nocdcBlobDir, nocdc.cache)
	}

	nbd := newMode("nbd", e.startNbd)
	if nbd.skip = subOK("nbd"); nbd.skip == "" {
		if !erofsSupported() {
			nbd.skip = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if dev, err := findFreeNbdDevice(); err != nil {
			nbd.skip = fmt.Sprintf("no free NBD device: %v (try: modprobe nbd)", err)
		} else {
			e.nbdDev = dev
		}
	}

	ublk := newMode("ublk", e.startUblk)
	if ublk.skip = subOK("ublk"); ublk.skip == "" {
		if !erofsSupported() {
			ublk.skip = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if !ublkAvailable() {
			ublk.skip = "ublk_drv unavailable (needs Linux 6.0+ and /dev/ublk-control; try: modprobe ublk_drv)"
		}
	}

	fan := newMode("fanotify", e.startFanotify)
	if fan.skip = subOK("fanotify"); fan.skip == "" {
		if maj, min := kernelVersion(t); maj < 6 || (maj == 6 && min < 15) {
			fan.skip = fmt.Sprintf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", maj, min)
		}
	}

	fileio := newMode("fileio", e.startFileio)
	if fileio.skip = subOK("fileio"); fileio.skip == "" {
		if !erofsSupported() {
			fileio.skip = "erofs not in /proc/filesystems — kernel lacks EROFS support"
		} else if maj, min := kernelVersion(t); maj < 6 || (maj == 6 && min < 12) {
			fileio.skip = fmt.Sprintf("kernel %d.%d < 6.12: CONFIG_EROFS_FS_BACKED_BY_FILE unavailable", maj, min)
		}
	}
	require.NoError(t, os.MkdirAll(filepath.Join(e.workDir, "fileio-export"), 0755))

	// Same serving path with the bootstrap prewarm off: the delta against the
	// fileio column is what FUSE_NOTIFY_STORE is worth.
	fileioNoWarm := newMode("fileio-nowarm", e.startFileioNoWarm)
	if fileioNoWarm.skip = fileio.skip; fileioNoWarm.skip == "" && os.Getenv("NYDUSFS_BENCH_FILEIO_NOWARM") == "" {
		fileioNoWarm.skip = "set NYDUSFS_BENCH_FILEIO_NOWARM=1 to enable the fileio-nowarm column"
	}
	require.NoError(t, os.MkdirAll(filepath.Join(e.workDir, "fileio-nowarm-export"), 0755))

	fileioBuffered := newMode("fileio-buffered", e.startFileioBuffered)
	fileioBuffered.skip = fileio.skip
	require.NoError(t, os.MkdirAll(filepath.Join(e.workDir, "fileio-buffered-export"), 0755))

	cerofs := &benchMode{
		name:  benchErofsfuse,
		mnt:   filepath.Join(e.workDir, "erofsfuse-mnt"),
		start: e.startErofsfuse,
	}
	require.NoError(t, os.MkdirAll(cerofs.mnt, 0755))
	if _, err := lookupCErofsFuseExecutable(); err != nil {
		cerofs.skip = err.Error()
	}

	v2 := &benchMode{
		name:  "v2-fuse",
		mnt:   filepath.Join(e.workDir, "v2-mnt"),
		cache: filepath.Join(e.workDir, "v2-cache"),
		start: e.startV2Fuse,
	}
	require.NoError(t, os.MkdirAll(v2.mnt, 0755))
	require.NoError(t, os.MkdirAll(v2.cache, 0755))
	if e.v2Bootstrap == "" {
		v2.skip = "set NYDUSFS_BENCH_V2_NYDUSD and NYDUSFS_BENCH_V2_IMAGE_BIN to enable the v2 column"
	}

	return []*benchMode{v2, fuse, nocdc, nbd, ublk, fan, fileio, fileioNoWarm, fileioBuffered, cerofs}
}

func (e *benchEnv) startV2Fuse(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "v2-mnt")
	config := fmt.Sprintf(`{
  "device": {
    "backend": { "type": "localfs", "config": { "dir": %q } },
    "cache": { "type": "blobcache", "config": { "work_dir": %q } }
  },
  "mode": "direct",
  "digest_validate": false,
  "enable_xattr": true,
  "iostats_files": false
}`, e.v2BlobDir, filepath.Join(e.workDir, "v2-cache"))
	configPath := filepath.Join(e.workDir, "v2.json")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0644))
	cmd := exec.Command(e.v2Nydusd,
		"--config", configPath,
		"--bootstrap", e.v2Bootstrap,
		"--mountpoint", mnt,
		"--log-level", "error",
	)
	exited := spawnDaemon(t, cmd, e.logPath("v2-fuse"))
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "v2 nydusd exited during startup", "%s", readFileOrEmpty(e.logPath("v2-fuse")))
		default:
		}
		return isMountpoint(mnt)
	}, 60*time.Second, 200*time.Millisecond, "v2 nydusd did not mount:\n%s", readFileOrEmpty(e.logPath("v2-fuse")))
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			unmountFuse(mnt)
		}
	}
}

// writeConfig writes one local-backend storage config per mode: per-mode blob
// dir and separate cache dirs. Prefetch stays disabled — a background prefetch
// would warm the cache mid-run and corrupt the cold measurements.
func (e *benchEnv) writeConfig(t *testing.T, name, blobDir, cacheDir string) {
	t.Helper()
	config := fmt.Sprintf(
		"backend:\n  type: local\n  config:\n    dir: %s\nstorage:\n  dir: %s\nprefetch:\n  scope: none\n",
		blobDir, cacheDir,
	)
	require.NoError(t, os.WriteFile(e.configPath(name), []byte(config), 0644))
}

func (e *benchEnv) configPath(name string) string {
	return filepath.Join(e.workDir, name+".yaml")
}

// apiSocket is where mode `name`'s daemon serves Prometheus /metrics.
func (e *benchEnv) apiSocket(name string) string {
	return filepath.Join(e.workDir, name+"-api.sock")
}

// backendReadMiB sums the backend_*_read_bytes counters from the daemon's
// metrics endpoint: bytes actually pulled from the backend, as opposed to
// cache-file disk allocation, which a 4 KiB block per tiny record inflates
// (a decoded block group publishes its records at block-aligned logical
// offsets, so `du` reports about 3x the real transfer on this corpus).
// Returns -1 when the socket is absent or unreadable.
func backendReadMiB(socket string) float64 {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://unix/metrics")
	if err != nil {
		return -1
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1
	}
	var total float64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// Only the by-kind counters: origin/proxy count the same bytes
		// again by source, so including them doubles the total.
		switch fields[0] {
		case "backend_ondemand_read_bytes", "backend_prefetch_read_bytes",
			"backend_redirect_read_bytes":
		default:
			continue
		}
		if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
			total += v
		}
	}
	return total / (1024 * 1024)
}

func (e *benchEnv) logPath(name string) string {
	return filepath.Join(e.workDir, name+".log")
}

func (e *benchEnv) logDir(name string) string {
	d := filepath.Join(e.workDir, name+"-logs")
	_ = os.MkdirAll(d, 0755)
	return d
}

// ---------------------------------------------------------------- daemons ----

// spawnDaemon starts cmd with stdout/stderr appended to logPath and returns
// the exited channel.
func spawnDaemon(t *testing.T, cmd *exec.Cmd, logPath string) chan struct{} {
	t.Helper()
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	_ = logFile.Close()
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	return exited
}

// terminateDaemon SIGTERMs cmd and waits up to benchStopTimeout before
// killing it.
func terminateDaemon(cmd *exec.Cmd, exited chan struct{}) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	select {
	case <-exited:
		return
	default:
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(benchStopTimeout):
		_ = cmd.Process.Kill()
		<-exited
	}
}

func (e *benchEnv) startFuse(t *testing.T) func() {
	return e.startFuseNamed(t, "fuse", e.bootstrap)
}

func (e *benchEnv) startFuseNocdc(t *testing.T) func() {
	return e.startFuseNamed(t, "fuse-nocdc", e.nocdcBootstrap)
}

func (e *benchEnv) startFuseNamed(t *testing.T, name, bootstrap string) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, name+"-mnt")
	cmd := exec.Command(e.nydusBin, "fuse",
		"--bootstrap", bootstrap,
		"--config", e.configPath(name),
		"--mountpoint", mnt,
		"--apiserver", "unix://"+e.apiSocket(name),
	)
	exited := spawnDaemon(t, cmd, e.logPath(name))
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "fuse daemon exited during startup", "%s", readFileOrEmpty(e.logPath(name)))
		default:
		}
		return isMountpoint(mnt)
	}, 60*time.Second, 200*time.Millisecond, "fuse daemon did not mount:\n%s", readFileOrEmpty(e.logPath(name)))
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			unmountFuse(mnt)
		}
	}
}

func (e *benchEnv) startNbd(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "nbd-mnt")
	cmd := exec.Command(e.nydusBin, "nbd",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("nbd"),
		"--device", e.nbdDev,
		"--mountpoint", mnt,
		"--log-level", "info",
		"--log-dir", e.logDir("nbd"),
	)
	exited := spawnDaemon(t, cmd, e.logPath("nbd"))
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "nbd daemon exited during startup", "%s", readFileOrEmpty(e.logPath("nbd")))
		default:
		}
		return isMountpoint(mnt)
	}, 60*time.Second, 200*time.Millisecond, "nbd daemon did not mount:\n%s", readFileOrEmpty(e.logPath("nbd")))
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
		waitNbdDeviceRelease(t, e.nbdDev)
	}
}

func (e *benchEnv) startUblk(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "ublk-mnt")
	logFile, err := os.Create(e.logPath("ublk"))
	require.NoError(t, err)
	cmd := exec.Command(e.nydusBin, "ublk",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("ublk"),
		"--log-level", "info",
		"--log-dir", e.logDir("ublk"),
		"--apiserver", "unix://"+e.apiSocket("ublk"),
	)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()

	// The daemon prints the /dev/ublkbN path on stdout once ready; tee every
	// line into the log file so it is preserved.
	var devPath string
	go func() {
		s := bufio.NewScanner(stdoutPipe)
		for s.Scan() {
			line := s.Text()
			_, _ = logFile.WriteString(line + "\n")
			trimmed := strings.TrimSpace(line)
			if devPath == "" && strings.HasPrefix(trimmed, "/dev/ublkb") {
				devPath = trimmed
			}
		}
	}()

	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "ublk daemon exited during startup", "%s", readFileOrEmpty(e.logPath("ublk")))
		default:
		}
		return devPath != ""
	}, 60*time.Second, 200*time.Millisecond, "ublk daemon did not report a device path:\n%s", readFileOrEmpty(e.logPath("ublk")))
	require.Eventually(t, func() bool {
		_, err := os.Stat(devPath)
		return err == nil
	}, 10*time.Second, 200*time.Millisecond, "%s did not appear", devPath)

	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", devPath, mnt).CombinedOutput()
	require.NoError(t, err, "failed to mount %s as erofs: %s", devPath, out)
	return func() {
		// Unmount BEFORE stopping the daemon: it serves I/O for its own
		// block device, so unmounting while it exits would deadlock.
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
		terminateDaemon(cmd, exited)
	}
}

func (e *benchEnv) startFanotify(t *testing.T) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, "fanotify-mnt")
	cmd := exec.Command(e.nydusBin, "fanotify",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath("fanotify"),
		"--mountpoint", mnt,
		"--log-level", "info",
		"--log-dir", e.logDir("fanotify"),
	)
	exited := spawnDaemon(t, cmd, e.logPath("fanotify"))
	logs := func() string {
		var b strings.Builder
		b.Write(readFileOrEmpty(e.logPath("fanotify")))
		entries, _ := os.ReadDir(e.logDir("fanotify"))
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				b.Write(readFileOrEmpty(filepath.Join(e.logDir("fanotify"), entry.Name())))
			}
		}
		return b.String()
	}
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "fanotify daemon exited during startup", "%s", logs())
		default:
		}
		return isMountpoint(mnt) && strings.Contains(logs(), "event loop ready")
	}, 60*time.Second, 200*time.Millisecond, "fanotify daemon did not mount:\n%s", logs())
	return func() {
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
	}
}

// startFileio exports the flattened image over FUSE and lets the kernel EROFS
// driver mount that file directly, so the daemon owns both mounts and tears
// them down in dependency order on shutdown.
func (e *benchEnv) startFileio(t *testing.T) func() {
	return e.startFileioMode(t, "fileio", true, true)
}

// startFileioNoWarm serves the same image with the FUSE_NOTIFY_STORE bootstrap
// push disabled, so the pair of columns isolates what that prewarm buys.
func (e *benchEnv) startFileioNoWarm(t *testing.T) func() {
	return e.startFileioMode(t, "fileio-nowarm", false, true)
}

// startFileioBuffered mounts without EROFS 'directio' (the daemon's default
// is on); the delta against the fileio column is what holding the image in
// the export's page cache as well buys and costs.
func (e *benchEnv) startFileioBuffered(t *testing.T) func() {
	return e.startFileioMode(t, "fileio-buffered", true, false)
}

func (e *benchEnv) startFileioMode(t *testing.T, name string, warmBootstrap, directIO bool) func() {
	t.Helper()
	mnt := filepath.Join(e.workDir, name+"-mnt")
	export := filepath.Join(e.workDir, name+"-export")
	cmd := exec.Command(e.nydusBin, "fileio",
		"--bootstrap", e.bootstrap,
		"--config", e.configPath(name),
		"--export-dir", export,
		"--mountpoint", mnt,
		"--warm-bootstrap", fmt.Sprintf("%t", warmBootstrap),
		"--direct-io", fmt.Sprintf("%t", directIO),
		"--log-level", "info",
		"--log-dir", e.logDir(name),
		"--apiserver", "unix://"+e.apiSocket(name),
	)
	exited := spawnDaemon(t, cmd, e.logPath(name))
	require.Eventually(t, func() bool {
		select {
		case <-exited:
			require.FailNowf(t, "fileio daemon exited during startup",
				"%s", readFileOrEmpty(e.logPath(name)))
		default:
		}
		return isMountpoint(mnt)
	}, 60*time.Second, 200*time.Millisecond, "fileio daemon did not mount:\n%s",
		readFileOrEmpty(e.logPath(name)))
	return func() {
		// The daemon unmounts EROFS before ending the export; the fallbacks
		// only matter if it died without running its shutdown path.
		terminateDaemon(cmd, exited)
		if isMountpoint(mnt) {
			_ = exec.Command("umount", mnt).Run()
			_ = exec.Command("umount", "-l", mnt).Run()
		}
		if isMountpoint(export) {
			_ = exec.Command("umount", "-l", export).Run()
		}
	}
}

func (e *benchEnv) startErofsfuse(t *testing.T) func() {
	t.Helper()
	bin := mustLookupCErofsFuse(t)
	return mountCErofsFuse(t, bin, e.bootstrap, filepath.Join(e.workDir, "erofsfuse-mnt"), e.blobPath)
}

// ublkAvailable reports whether the ublk_drv module is loadable and its
// control device is present. Mirrors the gating TestUblkTarget does.
func ublkAvailable() bool {
	if err := exec.Command("modprobe", "ublk_drv").Run(); err != nil {
		return false
	}
	if _, err := os.Stat("/dev/ublk-control"); err != nil {
		return false
	}
	return true
}

// cacheDirUsedBytes returns the allocated (not apparent) MiB of the blob
// cache files in cacheDir.
func cacheDirUsedBytes(cacheDir string) float64 {
	var total int64
	matches, _ := filepath.Glob(filepath.Join(cacheDir, "*.blob.data"))
	for _, m := range matches {
		total += usedBytes(m)
	}
	return float64(total) / (1024 * 1024)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ----------------------------------------------------------------- output ----

func printBenchTable(t *testing.T, modes []*benchMode, results map[string]*benchModeResult) {
	type row struct {
		label string
		key   string
		unit  string
		get   func(r *benchResult) float64
	}

	bw := func(r *benchResult) float64 { return r.ReadBW }
	iops := func(r *benchResult) float64 { return r.ReadIOPS }
	lat := func(r *benchResult) float64 { return r.ReadLat }

	var active []*benchMode
	for _, m := range modes {
		if results[m.name] != nil {
			active = append(active, m)
		}
	}

	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.Style().Options.SeparateRows = false
	header := table.Row{"Benchmark"}
	colCfg := []table.ColumnConfig{{Number: 1, Align: text.AlignLeft}}
	for i, m := range active {
		header = append(header, m.name)
		colCfg = append(colCfg, table.ColumnConfig{Number: 2 + i, Align: text.AlignRight})
	}
	tw.AppendHeader(header)
	tw.SetColumnConfigs(colCfg)

	appendRow := func(label string, cell func(res *benchModeResult) string) {
		cells := table.Row{label}
		for _, m := range active {
			cells = append(cells, cell(results[m.name]))
		}
		tw.AppendRow(cells)
	}

	appendRow("Mount ready", func(res *benchModeResult) string {
		return fmt.Sprintf("%.2f s", res.mountSec)
	})
	appendRow("Cold metadata walk", func(res *benchModeResult) string {
		return fmt.Sprintf("%.3f s", res.coldWalkSec)
	})
	appendRow("Cold walk rate", func(res *benchModeResult) string {
		if res.coldWalkSec <= 0 {
			return "—"
		}
		return fmt.Sprintf("%.0f ent/s", float64(res.coldWalkEntries)/res.coldWalkSec)
	})
	appendRow("Cold walk + xattr", func(res *benchModeResult) string {
		return fmt.Sprintf("%.3f s", res.coldXattrWalkSec)
	})
	appendRow("  xattr delta", func(res *benchModeResult) string {
		return fmt.Sprintf("%+.3f s", res.coldXattrWalkSec-res.coldWalkSec)
	})
	appendRow("Negative lookup ops/s", func(res *benchModeResult) string {
		return fmt.Sprintf("%.0f op/s", res.negativeLookupOps)
	})
	appendRow("First 1MiB cold read", func(res *benchModeResult) string {
		return fmt.Sprintf("%.3f s", res.firstReadSec)
	})
	appendRow("Cold seq read (64MiB)", func(res *benchModeResult) string {
		return fmt.Sprintf("%.1f MiB/s", res.coldSeqMiBps)
	})
	appendRow("  page cache used", func(res *benchModeResult) string {
		return fmt.Sprintf("%.1f MiB", res.coldSeqCachedMiB)
	})
	appendRow("Backend read (that 64MiB)", func(res *benchModeResult) string {
		if res.fetchedMiB < 0 {
			return "—"
		}
		return fmt.Sprintf("%.1f MiB", res.fetchedMiB)
	})
	appendRow("Cold rand read IOPS (4K)", func(res *benchModeResult) string {
		return fmt.Sprintf("%.0f IOPS", res.coldRandIOPS)
	})
	appendRow("Cold rand read Lat (4K)", func(res *benchModeResult) string {
		return fmt.Sprintf("%.0f µs", res.coldRandLatUs)
	})

	// Steady-state rows: only populated under NYDUSFS_BENCH_WARM. They say
	// little about container start, and once every mode's metadata is in the
	// kernel's caches they largely measure the same page-cache path.
	rows := []row{
		{"Seq Read BW (128K)", "seq_read_128k", "MiB/s", bw},
		{"Rand Read BW (128K)", "rand_read_128k", "MiB/s", bw},
		{"Seq Read BW (4K)", "seq_read_4k", "MiB/s", bw},
		{"Rand Read IOPS (4K)", "rand_read_4k", "IOPS", iops},
		{"Rand Read Lat (4K)", "rand_read_4k", "µs", lat},
		{"Seq 4t BW (128K)", "seq_read_4t_128k", "MiB/s", bw},
		{"Rand 4t BW (128K)", "rand_read_4t_128k", "MiB/s", bw},
		{"Seq 4t BW (4K)", "seq_read_4t_4k", "MiB/s", bw},
		{"Rand 4t BW (4K)", "rand_read_4t_4k", "MiB/s", bw},
		{"Stat IOPS", "stat", "IOPS", iops},
		{"Stat Latency", "stat", "µs", lat},
		{"Readdir IOPS", "readdir", "IOPS", iops},
		{"Readdir Latency", "readdir", "µs", lat},
		{"Listxattr IOPS", "listxattr", "IOPS", iops},
		{"Listxattr Latency", "listxattr", "µs", lat},
		{"Getxattr IOPS", "getxattr", "IOPS", iops},
		{"Getxattr Latency", "getxattr", "µs", lat},
		{"Readdir+stat (ls -l) IOPS", "readdir_stat", "IOPS", iops},
		{"Readdir+stat (ls -l) Latency", "readdir_stat", "µs", lat},
	}
	if os.Getenv("NYDUSFS_BENCH_WARM") != "" {
		tw.AppendSeparator()
		for _, r := range rows {
			appendRow(r.label, func(res *benchModeResult) string {
				if br, ok := res.bench[r.key]; ok && br != nil {
					return fmt.Sprintf("%.1f %s", r.get(br), r.unit)
				}
				return "—"
			})
		}
	}

	var skipped []string
	for _, m := range modes {
		if m.skip != "" {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", m.name, m.skip))
		}
	}
	suffix := ""
	if len(skipped) > 0 {
		suffix = "\nSkipped modes: " + strings.Join(skipped, "; ")
	}
	t.Log("\nCold-start Performance Comparison (local backend, cold page cache)\n" + tw.Render() + suffix)
}

// ----------------------------------------------------------- shared suite ----

// runBenchmarks executes the full I/O and metadata benchmark suite and
// returns the per-benchmark results keyed by name. dropCaches is called
// before each fio job to force cache-miss reads. Every job passes
// --invalidate=0: fio's default invalidate=1 fadvises the target file out of
// the page cache at job start — cache state must be controlled by dropCaches
// alone.
func runBenchmarks(t *testing.T, fioBin, targetFile, statDir, readdirDir string) map[string]*benchResult {
	require.FileExists(t, targetFile)

	fioRuntime := corpus.EnvInt("NYDUSFS_PERF_FIO_RUNTIME", 8)
	fioSeqNumjobs := corpus.EnvInt("NYDUSFS_PERF_FIO_SEQ_NUMJOBS", 4)
	fioRandNumjobs := corpus.EnvInt("NYDUSFS_PERF_FIO_RAND_NUMJOBS", 4)
	results := make(map[string]*benchResult)

	dropCaches(t)
	results["seq_read_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read", "--filename=" + targetFile,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})

	dropCaches(t)
	results["rand_read_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read", "--filename=" + targetFile,
		"--rw=randread", "--bs=128k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})

	dropCaches(t)
	results["seq_read_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4k", "--filename=" + targetFile,
		"--rw=read", "--bs=4k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})

	dropCaches(t)
	results["rand_read_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4k", "--filename=" + targetFile,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		"--numjobs=1", fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based", "--readonly",
	})

	dropCaches(t)
	results["seq_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + targetFile,
		"--rw=read", "--bs=128k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["rand_read_4t_128k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + targetFile,
		"--rw=randread", "--bs=128k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["seq_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=seq_read_4t", "--filename=" + targetFile,
		"--rw=read", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioSeqNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["rand_read_4t_4k"] = runFio(t, fioBin, []string{
		"--name=rand_read_4t", "--filename=" + targetFile,
		"--rw=randread", "--bs=4k", "--direct=0", "--invalidate=0",
		fmt.Sprintf("--numjobs=%d", fioRandNumjobs), fmt.Sprintf("--runtime=%d", fioRuntime), "--ramp_time=2", "--time_based",
		"--readonly", "--group_reporting",
	})

	dropCaches(t)
	results["stat"] = benchStat(t, statDir)

	dropCaches(t)
	results["readdir"] = benchReaddir(t, readdirDir)
	return results
}

// benchStat repeatedly stats every file in dir for the configured metadata duration and
// reports the achieved ops/s and latency.
func benchStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 3)) * time.Second

	var files []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}

		return nil
	})
	require.NotEmpty(t, files)

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, f := range files {
			_, _ = os.Stat(f)
		}

		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(files))
	return &benchResult{
		Name:     "stat",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchReaddir repeatedly reads every subdirectory of dir for the configured
// metadata duration and reports the achieved ops/s and latency.
func benchReaddir(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_READDIR_META_SECS", 3)) * time.Second
	passesPerDir := corpus.EnvInt("NYDUSFS_PERF_READDIR_PASSES_PER_DIR", 8)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(dir, entry.Name()))
		}
	}
	require.NotEmpty(t, dirs)

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, dir := range dirs {
			for range passesPerDir {
				_, _ = os.ReadDir(dir)
			}
		}

		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(dirs) * passesPerDir)
	return &benchResult{
		Name:     "readdir",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// addMetaBenchmarks runs the metadata-only benchmarks (listxattr, getxattr,
// readdir+stat) and inserts their results into the provided map.
func addMetaBenchmarks(t *testing.T, results map[string]*benchResult, xattrDir, xattrName, statDir string) {
	t.Helper()

	if xattrDir != "" {
		results["listxattr"] = benchListxattr(t, xattrDir)
		if xattrName != "" {
			results["getxattr"] = benchGetxattr(t, xattrDir, xattrName)
		}
	}
	results["readdir_stat"] = benchReaddirStat(t, statDir)
}

// benchListxattr repeatedly calls listxattr on every regular file in dir for
// the configured metadata duration and reports the achieved ops/s and latency.
// Returns nil when no regular files are found.
func benchListxattr(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 3)) * time.Second

	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil
	}

	buf := make([]byte, 512)
	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, f := range files {
			_, _ = syscall.Listxattr(f, buf)
		}
		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(files))
	return &benchResult{
		Name:     "listxattr",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchGetxattr repeatedly calls getxattr(name) on every regular file in dir
// for the configured metadata duration and reports the achieved ops/s and
// latency. Returns nil when no regular files are found.
func benchGetxattr(t *testing.T, dir, xattrName string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 3)) * time.Second

	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil
	}

	buf := make([]byte, 256)
	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		for _, f := range files {
			_, _ = syscall.Getxattr(f, xattrName, buf)
		}
		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations * len(files))
	return &benchResult{
		Name:     "getxattr",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchReaddirStat repeatedly reads dir entries and lstats each one,
// simulating an "ls -l" workload, for the configured metadata duration.
// Returns nil when dir has no entries.
func benchReaddirStat(t *testing.T, dir string) *benchResult {
	metaDuration := time.Duration(corpus.EnvInt("NYDUSFS_PERF_META_SECS", 3)) * time.Second

	// Verify the directory is non-empty.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	if len(entries) == 0 {
		return nil
	}

	iterations := 0
	start := time.Now()
	deadline := start.Add(metaDuration)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(dir)
		for _, ent := range ents {
			_, _ = os.Lstat(filepath.Join(dir, ent.Name()))
		}
		iterations++
	}

	elapsed := time.Since(start)
	totalOps := float64(iterations)
	return &benchResult{
		Name:     "readdir_stat",
		ReadIOPS: totalOps / elapsed.Seconds(),
		ReadLat:  elapsed.Seconds() / totalOps * 1e6,
	}
}

// benchResult is the per-job summary extracted from a benchmark run.
type benchResult struct {
	// A short name identifying the benchmark, e.g. "seq_read_128k".
	Name string

	// Throughput in MB/s.
	ReadBW float64

	// I/O operations per second.
	ReadIOPS float64

	// Average latency in microseconds.
	ReadLat float64
}

// fioJSONResult mirrors the subset of fio's JSON output we consume.
type fioJSONResult struct {
	Jobs []struct {
		Jobname string `json:"jobname"`
		Read    struct {
			Bw    float64 `json:"bw"` // KB/s
			Iops  float64 `json:"iops"`
			LatNs struct {
				Mean float64 `json:"mean"` // Nanoseconds
			} `json:"lat_ns"`
		} `json:"read"`
	} `json:"jobs"`
}

// runFio runs a single fio job with JSON output and returns its summary.
func runFio(t *testing.T, fioBin string, args []string) *benchResult {
	out, err := exec.Command(fioBin, append([]string{"--output-format=json"}, args...)...).CombinedOutput()
	require.NoError(t, err, "fio failed: %s", string(out))

	var result fioJSONResult
	require.NoError(t, json.Unmarshal(out, &result))
	require.NotEmpty(t, result.Jobs)

	job := result.Jobs[0]
	return &benchResult{
		Name:     job.Jobname,
		ReadBW:   job.Read.Bw / 1024.0,
		ReadIOPS: job.Read.Iops,
		ReadLat:  job.Read.LatNs.Mean / 1000.0,
	}
}
