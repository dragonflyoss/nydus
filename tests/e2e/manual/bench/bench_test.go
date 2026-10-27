//go:build manual

//e2e:serial benchmarks need an idle host: anything running alongside skews the numbers

// Package bench is the cold-start performance benchmark: `nydus fuse`,
// `nydus nbd`, `nydus ublk`, `nydus fanotify` and `nydus fileio` (plus
// optional C erofsfuse and nydus v2 columns) all serve the same locally
// built image (local backend, prefetch disabled, a fresh cache per mount),
// so the comparison isolates the read transport:
//
//	FUSE:      page-cache miss -> FUSE request -> daemon chunk map check +
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
// Methodology (per mode): drop the page cache, mount with an empty cache,
// then take a sequence of measurements in which each one touches data or
// metadata this mode has not touched yet:
//
//	mount ready         daemon up and the tree mountable
//	cold metadata walk  one readdir+lstat pass over the whole tree, taken
//	                    first so nothing has warmed it: the only row a
//	                    bootstrap prewarm can move
//	cold walk + xattr   the same pass with a listxattr per entry, on a fresh
//	                    mount; the delta is what xattrs cost on first access
//	first 1MiB          first-byte latency on an untouched file
//	cold seq read       one pass over that file, backend fetch included
//	data fetched        bytes pulled from the backend for exactly that file,
//	                    snapshotted before anything else fetches
//	cold rand read      a non-repeating 4K random pass over a second file
//	                    this mode has never opened
//
// Nothing here is a steady-state loop. Container start reads a rootfs once;
// looping over the same inodes would report the speed of whichever cache
// ended up holding them, which after the first pass is the kernel's page
// cache in every mode. Set NYDUSFS_BENCH_WARM=1 to append the steady-state
// fio and metadata rows for regression tracking.
//
// Modes the host cannot run (missing kernel module, old kernel, feature not
// compiled in) are left out and listed under the table.
//
// Run it as root with the manual tag and fio installed:
//
//	go test -tags manual -run TestBench -v -timeout 2h ./manual/bench/
//
// fanotify needs its cache on ext4, so point TMPDIR at one. Knobs (all
// optional):
//
//	NYDUSFS_PERF_LARGE_FILE_COUNT        large files for the read benchmarks (default 8)
//	NYDUSFS_PERF_LARGE_FILE_SIZE         size of each large file (default 64MiB)
//	NYDUSFS_PERF_MEDIUM_FILE_COUNT       medium files in the corpus (default 256)
//	NYDUSFS_PERF_MEDIUM_FILE             size of each medium file (default 1MiB)
//	NYDUSFS_PERF_SMALL_FILE_COUNT        small files for the stat benchmark (default 10000)
//	NYDUSFS_PERF_FIO_RUNTIME             fio duration in seconds (default 8, after a 2s ramp)
//	NYDUSFS_PERF_FIO_SEQ_NUMJOBS         sequential multi-thread job count (default 4)
//	NYDUSFS_PERF_FIO_RAND_NUMJOBS        random multi-thread job count (default 4)
//	NYDUSFS_PERF_READDIR_DIRS            directories of the readdir corpus (default 128)
//	NYDUSFS_PERF_READDIR_FILES_PER_DIR   files per directory of the readdir corpus (default 256)
//	NYDUSFS_PERF_META_SECS               metadata benchmark duration in seconds (default 3)
//	NYDUSFS_PERF_READDIR_META_SECS       readdir benchmark duration in seconds (default 3)
//	NYDUSFS_PERF_READDIR_PASSES_PER_DIR  os.ReadDir calls per directory per iteration (default 8)
//	NYDUSFS_PERF_COLD_RAND_IO_SIZE       bytes read by the cold random pass (default 16MiB)
//	NYDUSFS_BENCH_MODES                  comma-separated modes to run; the rest are left out
//	NYDUSFS_BENCH_WARM                   also run and print the steady-state rows
//	NYDUSFS_BENCH_FILEIO_NOWARM          add the fileio-nowarm column (no FUSE_NOTIFY_STORE prewarm)
//	NYDUSFS_BENCH_V2_NYDUSD, NYDUSFS_BENCH_V2_IMAGE_BIN
//	                                     nydus v2 binaries; both set adds the v2-fuse column
//	EROFS_C_FUSE                         the erofsfuse binary for its column
package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// TestBench measures every serving mode available on the host against the
// same image and prints one comparison table.
func TestBench(t *testing.T) {
	env.RequireRoot(t)
	fio := env.RequireTool(t, "fio")
	nydus := env.Nydus(t)

	work := env.WorkDir(t)
	src := filepath.Join(work, "corpus")
	t.Log("Generating performance corpus...")
	corpus.MakePerfCorpus(t, src)
	t.Log("Building the image (zstd, 1MiB chunks)...")
	img := buildImage(t, work, src)
	v2 := buildV2Image(t, work, src)

	modes := benchModes(t, nydus, img, v2)
	// NYDUSFS_BENCH_MODES=fileio,fileio-buffered runs just those columns:
	// a mode costs minutes, so comparing two should not pay for the rest.
	if filter := os.Getenv("NYDUSFS_BENCH_MODES"); filter != "" {
		wanted := map[string]bool{}
		for _, name := range strings.Split(filter, ",") {
			wanted[strings.TrimSpace(name)] = true
		}
		for _, m := range modes {
			if wanted[m.name] {
				env.Require(t, m.skip == "", "requested benchmark mode %s unavailable: %s", m.name, m.skip)
				delete(wanted, m.name)
				continue
			}
			if m.skip == "" {
				m.skip = "filtered out by NYDUSFS_BENCH_MODES"
			}
		}
		require.Empty(t, wanted, "unknown benchmark mode requested")
	}

	results := map[string]*modeResult{}
	for _, m := range modes {
		if m.skip != "" {
			t.Logf("=== %s: left out (%s) ===", m.name, m.skip)
			continue
		}
		t.Logf("=== %s ===", m.name)
		results[m.name] = runMode(t, fio, m)
	}
	require.NotEmpty(t, results, "no serving mode is available on this host")
	printTable(t, modes, results)
	reportResults(t, results)
}
