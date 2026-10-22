//go:build manual

package bench

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Fixed paths of corpus.MakePerfCorpus.
const (
	targetRel  = "large/file_0.bin"
	randRel    = "large/file_1.bin"
	statRel    = "small"
	readdirRel = "dirs"
	xattrRel   = "xattrs"
	xattrName  = "user.bench"
)

// benchLayout is the image every mode serves.
var benchLayout = fixture.Layout{Name: "bench", Args: []string{"--compressor", "zstd", "--chunk-size", "1048576"}}

func buildImage(t *testing.T, work, src string) fixture.Image {
	t.Helper()
	blobDir := filepath.Join(work, "blobs")
	bootstrap := filepath.Join(work, "image.bootstrap")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, src, benchLayout)
	return fixture.Image{
		Name:      benchLayout.Name,
		Layout:    benchLayout,
		Corpus:    "perf",
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     []string{blob},
		Source:    src,
	}
}

// benchMode is one way of serving the image. All measurements are the same
// for every mode.
type benchMode struct {
	name string
	// skip, when set, says why the host cannot run the mode; its column is
	// left out.
	skip string
	// start serves the image with an empty cache and returns once it is
	// mounted.
	start func(t *testing.T) *served
}

// served is a mounted mode.
type served struct {
	root string
	// api serves the daemon's metrics; nil when it has no apiserver.
	api *mount.API
	// cache is the nydus cache directory; empty when the mode has none.
	cache string
	stop  func()
}

// adapterMode serves the image through an internal/mount adapter, with
// extra daemon flags.
func adapterMode(name string, a mount.Adapter, img fixture.Image, args ...string) *benchMode {
	return &benchMode{name: name, start: func(t *testing.T) *served {
		m := mount.Mount(t, a, img, mount.Options{Mode: mount.Cold, Args: args})
		return &served{root: m.Root, api: m.API, cache: m.CacheDir, stop: m.Unmount}
	}}
}

// benchModes lists every mode, probing which the host can run. A probe never
// fails the test: a missing mode only loses its column.
func benchModes(t *testing.T, nydus string, img fixture.Image, v2 *v2Image) []*benchMode {
	t.Helper()
	subcommand := func(sub string) string {
		if out, err := exec.Command(nydus, sub, "--help").CombinedOutput(); err != nil {
			return fmt.Sprintf("nydus lacks the %s subcommand (build with --features cli,%s): %s", sub, sub, firstLine(out))
		}
		return ""
	}
	const noErofs = "kernel lacks EROFS support"
	major, minor := env.KernelVersion()

	fuse := adapterMode("fuse", mount.FUSE{}, img)
	if fuse.skip = subcommand("fuse"); fuse.skip == "" && !env.HasFilesystem("fuse") {
		fuse.skip = "kernel lacks FUSE support"
	}

	nbd := &benchMode{name: "nbd"}
	if nbd.skip = subcommand("nbd"); nbd.skip == "" {
		if !env.HasFilesystem("erofs") {
			nbd.skip = noErofs
		} else if dev, err := findFreeNbdDevice(); err != nil {
			nbd.skip = fmt.Sprintf("no free NBD device: %v (try: modprobe nbd)", err)
		} else {
			nbd.start = func(t *testing.T) *served { return startNbd(t, nydus, img, dev) }
		}
	}

	ublk := &benchMode{name: "ublk", start: func(t *testing.T) *served { return startUblk(t, nydus, img) }}
	if ublk.skip = subcommand("ublk"); ublk.skip == "" {
		if !env.HasFilesystem("erofs") {
			ublk.skip = noErofs
		} else if !ublkAvailable() {
			ublk.skip = "ublk_drv unavailable (needs Linux 6.0+ and /dev/ublk-control; try: modprobe ublk_drv)"
		}
	}

	fan := &benchMode{name: "fanotify", start: func(t *testing.T) *served { return startFanotify(t, nydus, img) }}
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
	// The bootstrap prewarm off: the delta against the fileio column is what
	// FUSE_NOTIFY_STORE is worth.
	fileioNoWarm := adapterMode("fileio-nowarm", mount.Fileio{}, img, "--warm-bootstrap", "false", "--direct-io", "true")
	if fileioNoWarm.skip = fileioSkip; fileioNoWarm.skip == "" && os.Getenv("NYDUSFS_BENCH_FILEIO_NOWARM") == "" {
		fileioNoWarm.skip = "set NYDUSFS_BENCH_FILEIO_NOWARM=1 to add the fileio-nowarm column"
	}
	// EROFS without 'directio': the delta against the fileio column is what
	// also holding the image in the export's page cache buys and costs.
	fileioBuffered := adapterMode("fileio-buffered", mount.Fileio{}, img, "--warm-bootstrap", "true", "--direct-io", "false")
	fileioBuffered.skip = fileioSkip

	erofsfuse := &benchMode{name: "erofsfuse"}
	if bin, err := lookupErofsfuse(); err != nil {
		erofsfuse.skip = err.Error()
	} else {
		erofsfuse.start = func(t *testing.T) *served { return startErofsfuse(t, bin, img) }
	}

	v2fuse := &benchMode{name: "v2-fuse", skip: "set NYDUSFS_BENCH_V2_NYDUSD and NYDUSFS_BENCH_V2_IMAGE_BIN to add the v2 column"}
	if v2 != nil {
		v2fuse.skip = ""
		v2fuse.start = func(t *testing.T) *served { return startV2Fuse(t, v2) }
	}

	return []*benchMode{v2fuse, fuse, nbd, ublk, fan, fileio, fileioNoWarm, fileioBuffered, erofsfuse}
}

// modeResult collects every measurement of one mode.
type modeResult struct {
	mountSec          float64
	coldWalkSec       float64
	coldWalkEntries   int
	coldXattrWalkSec  float64
	negativeLookupOps float64
	bigDirLookupOps   float64
	firstReadSec      float64
	coldSeqMiBps      float64
	coldSeqCachedMiB  float64 // page cache growth across the cold read
	fetchedMiB        float64 // < 0 when unknown
	coldRandIOPS      float64
	coldRandLatUs     float64
	warm              map[string]*benchResult // nil unless NYDUSFS_BENCH_WARM is set
}

// runMode measures one mode end to end. Every measurement touches data or
// metadata this mode has not touched yet, with the page cache dropped
// beforehand, because first access is what decides container start time.
func runMode(t *testing.T, fio string, m *benchMode) *modeResult {
	t.Helper()
	dropCaches(t)
	res := &modeResult{fetchedMiB: -1}
	func() {
		mountStart := time.Now()
		s := m.start(t)
		defer s.stop()
		res.mountSec = time.Since(mountStart).Seconds()
		t.Logf("  mount ready: %.2fs", res.mountSec)

		// First, before anything else touches the tree: this is the only
		// measurement a bootstrap prewarm can move.
		res.coldWalkSec, res.coldWalkEntries = coldMetadataWalk(t, s.root, false)
		t.Logf("  cold metadata walk: %d entries in %.3fs (%.0f entries/s)",
			res.coldWalkEntries, res.coldWalkSec, float64(res.coldWalkEntries)/res.coldWalkSec)

		res.negativeLookupOps = negativeLookup(t, filepath.Join(s.root, statRel))
		t.Logf("  negative lookups: %.0f ops/s", res.negativeLookupOps)

		dropCaches(t)
		target := filepath.Join(s.root, targetRel)
		readStart := time.Now()
		_, err := readSlice(target, 0, 1)
		require.NoError(t, err, "first cold read failed")
		res.firstReadSec = time.Since(readStart).Seconds()
		t.Logf("  first 1MiB cold read: %.3fs", res.firstReadSec)

		// A single cold pass over a file nothing has read: the end-to-end
		// on-demand fetch path, backend included.
		cachedBefore := cachedMiB(t)
		seqStart := time.Now()
		n := readWhole(t, target)
		res.coldSeqMiBps = float64(n) / (1 << 20) / time.Since(seqStart).Seconds()
		res.coldSeqCachedMiB = cachedMiB(t) - cachedBefore
		t.Logf("  cold seq read: %.1f MiB at %.1f MiB/s, page cache +%.1f MiB",
			float64(n)/(1<<20), res.coldSeqMiBps, res.coldSeqCachedMiB)

		// Snapshot while the only data ever fetched is that one file: the
		// backend counters where the daemon serves metrics, the cache's disk
		// allocation otherwise.
		if fetched := backendReadMiB(s.api); fetched >= 0 {
			res.fetchedMiB = fetched
			t.Logf("  backend bytes for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), res.fetchedMiB)
		} else if s.cache != "" {
			res.fetchedMiB = cacheUsedMiB(s.cache)
			t.Logf("  cache allocation for %.1f MiB of file: %.1f MiB", float64(n)/(1<<20), res.fetchedMiB)
		}

		dropCaches(t)
		res.coldRandIOPS, res.coldRandLatUs = coldRandRead(t, fio, filepath.Join(s.root, randRel))
		t.Logf("  cold rand read 4K: %.0f IOPS, %.0f µs", res.coldRandIOPS, res.coldRandLatUs)

		if os.Getenv("NYDUSFS_BENCH_WARM") != "" {
			statDir := filepath.Join(s.root, statRel)
			res.warm = runWarmBenchmarks(t, fio, target, statDir, filepath.Join(s.root, readdirRel))
			dropCaches(t)
			addMetaBenchmarks(t, res.warm, filepath.Join(s.root, xattrRel), xattrName, statDir)
		}
	}()

	// The xattr pass needs a mount of its own to be comparable with the
	// plain walk: a second walk in one session finds the daemon's mappings
	// already built, and dropping the page cache does not evict those.
	dropCaches(t)
	func() {
		s := m.start(t)
		defer s.stop()
		res.coldXattrWalkSec, _ = coldMetadataWalk(t, s.root, true)
		t.Logf("  cold walk + xattr: %.3fs (xattr delta %+.3fs)",
			res.coldXattrWalkSec, res.coldXattrWalkSec-res.coldWalkSec)
	}()
	dropCaches(t)
	func() {
		s := m.start(t)
		defer s.stop()
		count := corpus.EnvInt("NYDUSFS_PERF_SMALL_FILE_COUNT", 10000)
		require.Positive(t, count)
		// Each positive lookup is issued once on a fresh mount, without a
		// preceding readdir/stat walk warming the dentries.
		start := time.Now()
		for i := count - 1; i >= 0; i-- {
			_, err := os.Lstat(filepath.Join(s.root, statRel, fmt.Sprintf("file_%04d.txt", i)))
			require.NoError(t, err)
		}
		res.bigDirLookupOps = float64(count) / time.Since(start).Seconds()
		t.Logf("  big directory cold positive lookup: %d entries, %.0f ops/s", count, res.bigDirLookupOps)
	}()
	return res
}

// coldMetadataWalk enumerates the whole mount once with the page cache cold:
// readdir every directory and lstat every entry, optionally adding a
// listxattr per entry.
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

// negativeLookup stats the same missing names over and over for one
// second, as module resolution does to a rootfs: a filesystem that caches
// negative dentries answers repeats from the dcache, one that does not pays a
// round trip per probe.
func negativeLookup(t *testing.T, dir string) float64 {
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
			_, err := os.Lstat(name)
			require.ErrorIs(t, err, os.ErrNotExist, "%s", name)
		}
		ops += len(names)
	}
	return float64(ops) / time.Since(start).Seconds()
}

// backendReadMiB sums the by-kind backend byte counters of the daemon's
// metrics: bytes actually pulled from the backend, as opposed to the cache's
// disk allocation, which a block per small record inflates. The by-source
// counters (origin, proxy) count the same bytes again. It returns -1 when
// the daemon serves no metrics.
func backendReadMiB(api *mount.API) float64 {
	if api == nil {
		return -1
	}
	body, err := api.Get("/metrics")
	if err != nil {
		return -1
	}
	m := mount.ParseMetrics(string(body))
	return (m.Sum("nydus_backend_read_bytes_total", `type="ondemand"`) + m.Sum("nydus_backend_read_bytes_total", `type="prefetch"`)) / (1 << 20)
}

// cacheUsedMiB returns the allocated (not apparent) MiB of the blob cache
// files in dir.
func cacheUsedMiB(dir string) float64 {
	var total int64
	matches, _ := filepath.Glob(filepath.Join(dir, "*.blob.data"))
	for _, m := range matches {
		var st unix.Stat_t
		if unix.Stat(m, &st) == nil {
			total += st.Blocks * 512
		}
	}
	return float64(total) / (1 << 20)
}

// cachedMiB reports the kernel's page cache from /proc/meminfo. Serving one
// byte can cache it more than once (the daemon's cache file, an export or a
// block device, the file read), and the growth across a cold read of a known
// size shows how many of those copies survive.
func cachedMiB(t *testing.T) float64 {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	require.NoError(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Cached:"); ok {
			var kb float64
			if _, err := fmt.Sscanf(rest, "%f kB", &kb); err == nil {
				return kb / 1024
			}
		}
	}
	return -1
}

// dropCaches flushes dirty data and drops the page cache, dentries and
// inodes.
func dropCaches(t *testing.T) {
	t.Helper()
	unix.Sync()
	require.NoError(t, os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o644))
	time.Sleep(500 * time.Millisecond)
}

// readSlice reads countMiB MiB starting at skipMiB MiB.
func readSlice(path string, skipMiB, countMiB int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(skipMiB<<20, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, countMiB<<20)
	n, err := io.ReadFull(f, buf)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		err = nil
	}
	return buf[:n], err
}

func readWhole(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	n, err := io.Copy(io.Discard, f)
	require.NoError(t, err)
	return n
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// printTable logs the comparison of every mode that ran.
func printTable(t *testing.T, modes []*benchMode, results map[string]*modeResult) {
	t.Helper()
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

	appendRow := func(label string, cell func(res *modeResult) string) {
		cells := table.Row{label}
		for _, m := range active {
			cells = append(cells, cell(results[m.name]))
		}
		tw.AppendRow(cells)
	}

	appendRow("Mount ready", func(res *modeResult) string { return fmt.Sprintf("%.2f s", res.mountSec) })
	appendRow("Cold metadata walk", func(res *modeResult) string { return fmt.Sprintf("%.3f s", res.coldWalkSec) })
	appendRow("Cold walk rate", func(res *modeResult) string {
		if res.coldWalkSec <= 0 {
			return "—"
		}
		return fmt.Sprintf("%.0f ent/s", float64(res.coldWalkEntries)/res.coldWalkSec)
	})
	appendRow("Cold walk + xattr", func(res *modeResult) string { return fmt.Sprintf("%.3f s", res.coldXattrWalkSec) })
	appendRow("  xattr delta", func(res *modeResult) string {
		return fmt.Sprintf("%+.3f s", res.coldXattrWalkSec-res.coldWalkSec)
	})
	appendRow("Negative lookup ops/s", func(res *modeResult) string { return fmt.Sprintf("%.0f op/s", res.negativeLookupOps) })
	appendRow("Big-dir cold lookup ops/s", func(res *modeResult) string { return fmt.Sprintf("%.0f op/s", res.bigDirLookupOps) })
	appendRow("First 1MiB cold read", func(res *modeResult) string { return fmt.Sprintf("%.3f s", res.firstReadSec) })
	appendRow("Cold seq read (64MiB)", func(res *modeResult) string { return fmt.Sprintf("%.1f MiB/s", res.coldSeqMiBps) })
	appendRow("  page cache used", func(res *modeResult) string { return fmt.Sprintf("%.1f MiB", res.coldSeqCachedMiB) })
	appendRow("Backend read (that 64MiB)", func(res *modeResult) string {
		if res.fetchedMiB < 0 {
			return "—"
		}
		return fmt.Sprintf("%.1f MiB", res.fetchedMiB)
	})
	appendRow("Cold rand read IOPS (4K)", func(res *modeResult) string { return fmt.Sprintf("%.0f IOPS", res.coldRandIOPS) })
	appendRow("Cold rand read Lat (4K)", func(res *modeResult) string { return fmt.Sprintf("%.0f µs", res.coldRandLatUs) })

	// The steady-state rows say little about container start: once every
	// mode's metadata is in the kernel's caches they largely measure the same
	// page-cache path.
	if os.Getenv("NYDUSFS_BENCH_WARM") != "" {
		tw.AppendSeparator()
		for _, r := range warmRows {
			appendRow(r.label, func(res *modeResult) string {
				if br := res.warm[r.key]; br != nil {
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
		suffix = "\nModes left out: " + strings.Join(skipped, "; ")
	}
	t.Log("\nCold-start Performance Comparison (local backend, cold page cache)\n" + tw.Render() + suffix)
}
