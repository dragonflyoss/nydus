package e2e

// Cross-process tests for the shared blob cache. Several `nydus fuse`
// processes are pointed at one --cache-dir, which is the state they contend
// on, and the assertions read back the cache directory and each process's
// Prometheus metrics.
//
// Some assertions below deliberately pin *current* behaviour that is known to
// be wrong; each one names the fix that will flip it. That keeps this file
// mergeable on its own and makes every later fix prove itself by turning a red
// assertion green.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Processes contending on one cache directory. Four is enough to show
// duplicate work without making the suite heavy.
const coreProcs = 4

const coreChunkSize = 4096

// coreMount is a running `nydus fuse` process together with the Unix
// socket its metrics are served on.
type coreMount struct {
	mnt  string
	sock string
	cmd  *exec.Cmd
}

type coreMountOption struct {
	bootstrap string
	blobDir   string
	cacheDir  string
	mnt       string
	prefetch  bool
	// fullPrefetch warms every blob rather than only the priority ones. Plain
	// merged images have no priority blobs, so without this a prefetching
	// mount does no work at all.
	fullPrefetch bool
}

// writePrefetchConfig renders the storage config needed to turn on all-blob
// prefetch, which has no command line flag of its own.
func writePrefetchConfig(t *testing.T, path, blobDir, cacheDir string) {
	t.Helper()
	config := fmt.Sprintf(`backend:
  type: local
  config:
    dir: %s
storage:
  dir: %s
prefetch:
  scope: all
  concurrent_blob_count: 4
`, blobDir, cacheDir)
	require.NoError(t, os.WriteFile(path, []byte(config), 0644))
}

// startCoreMount mounts an image and waits until both the mountpoint and
// the metrics endpoint answer.
func startCoreMount(t *testing.T, nydusBin string, opt coreMountOption) *coreMount {
	t.Helper()

	_ = exec.Command("fusermount", "-u", opt.mnt).Run()
	require.NoError(t, os.MkdirAll(opt.mnt, 0755))
	require.NoError(t, os.MkdirAll(opt.cacheDir, 0755))

	// Keep the socket out of the test's temp dir: Unix socket paths are capped
	// near 108 bytes and TMPDIR is redirected into the repo for some targets.
	sockDir, err := os.MkdirTemp("", "nydus-acc")
	require.NoError(t, err)
	sock := filepath.Join(sockDir, "api.sock")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	args := []string{
		"fuse",
		"--bootstrap", opt.bootstrap,
		"--blob-dir", opt.blobDir,
		"--cache-dir", opt.cacheDir,
		"--mountpoint", opt.mnt,
		"--apiserver", "unix://" + sock,
	}
	if opt.prefetch {
		args = append(args, "--prefetch")
	}
	if opt.fullPrefetch {
		configPath := filepath.Join(sockDir, "storage.yaml")
		writePrefetchConfig(t, configPath, opt.blobDir, opt.cacheDir)
		args = append(args, "--config", configPath)
	}

	cmd := exec.Command(nydusBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	m := &coreMount{mnt: opt.mnt, sock: sock, cmd: cmd}
	t.Cleanup(m.stop)

	require.Eventually(t, func() bool {
		return isMountpoint(opt.mnt)
	}, 30*time.Second, 100*time.Millisecond, "nydus fuse failed to mount %s", opt.mnt)
	require.Eventually(t, func() bool {
		_, err := m.tryMetrics()
		return err == nil
	}, 30*time.Second, 100*time.Millisecond, "metrics endpoint %s never came up", sock)

	return m
}

func (m *coreMount) stop() {
	_ = exec.Command("fusermount", "-u", m.mnt).Run()
	if m.cmd.Process == nil {
		return
	}
	_ = m.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = m.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = m.cmd.Process.Kill()
	}
}

// kill terminates the process without giving it a chance to clean up, standing
// in for a crash.
func (m *coreMount) kill(t *testing.T) {
	t.Helper()
	require.NotNil(t, m.cmd.Process)
	require.NoError(t, m.cmd.Process.Kill())
	_, _ = m.cmd.Process.Wait()
	_ = exec.Command("fusermount", "-u", m.mnt).Run()
}

func (m *coreMount) tryMetrics() (map[string]float64, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", m.sock)
			},
		},
	}
	resp, err := client.Get("http://localhost/metrics")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics returned %s", resp.Status)
	}
	return parsePrometheusText(resp.Body)
}

func (m *coreMount) metrics(t *testing.T) map[string]float64 {
	t.Helper()
	values, err := m.tryMetrics()
	require.NoError(t, err)
	return values
}

// parsePrometheusText reads the exposition format into a name-to-value map.
// Labeled series keep their `{...}` suffix in the key.
func parsePrometheusText(r io.Reader) (map[string]float64, error) {
	values := make(map[string]float64)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.LastIndexByte(line, ' ')
		if idx < 0 {
			continue
		}
		value, err := strconv.ParseFloat(line[idx+1:], 64)
		if err != nil {
			continue
		}
		values[line[:idx]] = value
	}
	return values, scanner.Err()
}

// coreFixture is two images sharing one blob, so the tests can tell
// per-image cache state apart from per-blob cache state.
//
//	image1 = blobA + blobB
//	image2 =         blobB + blobC
type coreFixture struct {
	blobDir    string
	blobA      string
	blobB      string
	blobC      string
	bootstrap1 string
	bootstrap2 string
	// file1 lives in blobA, shared lives in blobB, file3 lives in blobC.
	files map[string][]byte
}

func buildCoreFixture(t *testing.T, nydusBin, root string) *coreFixture {
	t.Helper()

	corpusA := filepath.Join(root, "corpusA")
	corpusB := filepath.Join(root, "corpusB")
	corpusC := filepath.Join(root, "corpusC")
	blobDir := filepath.Join(root, "blobs")

	files := map[string][]byte{
		"file1.bin": deterministicBytes(1<<20+4096, 1),
		// Large enough to span several block groups: with only one block group per blob a
		// per-process refetch would barely register in the fill counter.
		"shared.bin": deterministicBytes(12<<20, 2),
		"file3.bin":  deterministicBytes(1<<20+2048, 3),
	}
	writeCorpus(t, corpusA, map[string][]byte{"file1.bin": files["file1.bin"]})
	writeCorpus(t, corpusB, map[string][]byte{"shared.bin": files["shared.bin"]})
	writeCorpus(t, corpusC, map[string][]byte{"file3.bin": files["file3.bin"]})

	// Distinct file names across the corpora keep overlay merge from shadowing
	// anything, so every blob stays reachable in the merged images.
	blobA := buildNydusFSImageToDir(t, nydusBin, "", blobDir, corpusA, coreChunkSize)
	blobB := buildNydusFSImageToDir(t, nydusBin, "", blobDir, corpusB, coreChunkSize)
	blobC := buildNydusFSImageToDir(t, nydusBin, "", blobDir, corpusC, coreChunkSize)

	bootstrap1 := filepath.Join(root, "image1.bootstrap")
	bootstrap2 := filepath.Join(root, "image2.bootstrap")
	mergeNydusBootstrap(t, nydusBin, bootstrap1, blobA, blobB)
	mergeNydusBootstrap(t, nydusBin, bootstrap2, blobB, blobC)

	return &coreFixture{
		blobDir:    blobDir,
		blobA:      blobA,
		blobB:      blobB,
		blobC:      blobC,
		bootstrap1: bootstrap1,
		bootstrap2: bootstrap2,
		files:      files,
	}
}

func writeCorpus(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0755))
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0644))
	}
}

// deterministicBytes builds incompressible-enough content that is stable across
// runs, so blob digests (and therefore cache keys) stay reproducible.
func deterministicBytes(size int, seed uint64) []byte {
	out := make([]byte, size)
	state := seed*6364136223846793005 + 1442695040888963407
	for i := range out {
		state = state*6364136223846793005 + 1442695040888963407
		out[i] = byte(state >> 33)
	}
	return out
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// cacheFileInode returns the inode of a cache sidecar, identifying the file
// across processes.
func cacheFileInode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "unexpected stat type for %s", path)
	return stat.Ino
}

func cacheEntries(t *testing.T, cacheDir, suffix string) []string {
	t.Helper()
	entries, err := os.ReadDir(cacheDir)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	var out []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), suffix) {
			out = append(out, filepath.Join(cacheDir, entry.Name()))
		}
	}
	return out
}

// readConcurrently has every mount read the same relative path at once, so the
// processes genuinely race on a cold cache instead of warming it for each
// other in turn.
func readConcurrently(t *testing.T, mounts []*coreMount, rel string) []string {
	t.Helper()

	start := make(chan struct{})
	digests := make([]string, len(mounts))
	errs := make([]error, len(mounts))

	var wg sync.WaitGroup
	for i, m := range mounts {
		wg.Add(1)
		go func(i int, m *coreMount) {
			defer wg.Done()
			<-start
			data, err := os.ReadFile(filepath.Join(m.mnt, rel))
			if err != nil {
				errs[i] = err
				return
			}
			digests[i] = sha256Bytes(data)
		}(i, m)
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "mount %d failed to read %s", i, rel)
	}
	return digests
}

func skipUnlessRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root to mount FUSE")
	}
}

// sumMetric adds one counter across every mount, which is how the duplicate
// work of processes sharing a cache directory shows up.
func sumMetric(t *testing.T, mounts []*coreMount, name string) float64 {
	t.Helper()
	var total float64
	for _, m := range mounts {
		total += m.metrics(t)[name]
	}
	return total
}

// TestCoreConcurrentColdReadIsConsistent covers the baseline guarantee:
// however much duplicate work the processes do, they all observe the same
// bytes and the cache never serves a torn block group.
func TestCacheSharingConcurrentColdReadIsConsistent(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)
	cacheDir := filepath.Join(root, "cache")

	mounts := make([]*coreMount, coreProcs)
	for i := range mounts {
		mounts[i] = startCoreMount(t, nydusBin, coreMountOption{
			bootstrap: fixture.bootstrap1,
			blobDir:   fixture.blobDir,
			cacheDir:  cacheDir,
			mnt:       filepath.Join(root, fmt.Sprintf("mnt%d", i)),
		})
	}

	digests := readConcurrently(t, mounts, "shared.bin")
	want := sha256Bytes(fixture.files["shared.bin"])
	for i, got := range digests {
		require.Equal(t, want, got, "mount %d read different bytes", i)
	}
}

// TestCoreConcurrentColdReadAmplification measures how much duplicate
// fetching the processes do, calibrated against a single process doing the
// same read so the assertion does not depend on the blob's block group count.
func TestCacheSharingConcurrentColdReadAmplification(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)

	// Baseline: one process filling a cold cache on its own.
	soloCache := filepath.Join(root, "cache-solo")
	solo := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap1,
		blobDir:   fixture.blobDir,
		cacheDir:  soloCache,
		mnt:       filepath.Join(root, "mnt-solo"),
	})
	readConcurrently(t, []*coreMount{solo}, "shared.bin")
	soloFill := solo.metrics(t)["cache_ondemand_fill_block_group"]
	require.Greater(t, soloFill, 1.0,
		"the read must span several block groups for the comparison below to mean anything")

	// Contended: the same read, from a cold cache, by several processes.
	sharedCache := filepath.Join(root, "cache-shared")
	mounts := make([]*coreMount, coreProcs)
	for i := range mounts {
		mounts[i] = startCoreMount(t, nydusBin, coreMountOption{
			bootstrap: fixture.bootstrap1,
			blobDir:   fixture.blobDir,
			cacheDir:  sharedCache,
			mnt:       filepath.Join(root, fmt.Sprintf("mnt-shared%d", i)),
		})
	}
	readConcurrently(t, mounts, "shared.bin")
	totalFill := sumMetric(t, mounts, "cache_ondemand_fill_block_group")

	t.Logf("cold read amplification: solo=%.0f block groups, %d processes=%.0f block groups (%.2fx)",
		soloFill, coreProcs, totalFill, totalFill/soloFill)

	// Whoever wins a block group's fetch right publishes it, and the processes that
	// waited find it ready instead of fetching it again, so the total should
	// match a single process doing the same read. One block group of slack covers a
	// filesystem that cannot provide the lock and falls back to refetching.
	require.LessOrEqual(t, totalFill, soloFill+1,
		"concurrent cold reads should not refetch the same block groups per process")
}

// TestCoreConcurrentPrefetchDeduplicates checks the path that already has
// cross-process exclusion: the per-blob prefetch lock should keep all but one
// process from streaming the blob.
func TestCacheSharingConcurrentPrefetchDeduplicates(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)

	soloCache := filepath.Join(root, "cache-solo")
	solo := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap:    fixture.bootstrap1,
		blobDir:      fixture.blobDir,
		cacheDir:     soloCache,
		mnt:          filepath.Join(root, "mnt-solo"),
		prefetch:     true,
		fullPrefetch: true,
	})
	var soloFill float64
	require.Eventually(t, func() bool {
		soloFill = solo.metrics(t)["cache_fill_block_group"]
		return soloFill > 0
	}, 60*time.Second, 200*time.Millisecond, "solo prefetch never filled a block group")

	sharedCache := filepath.Join(root, "cache-shared")
	mounts := make([]*coreMount, coreProcs)
	for i := range mounts {
		mounts[i] = startCoreMount(t, nydusBin, coreMountOption{
			bootstrap:    fixture.bootstrap1,
			blobDir:      fixture.blobDir,
			cacheDir:     sharedCache,
			mnt:          filepath.Join(root, fmt.Sprintf("mnt-shared%d", i)),
			prefetch:     true,
			fullPrefetch: true,
		})
	}

	// Prefetch runs in the background, so wait for it to settle rather than
	// sampling a partial total.
	var totalFill float64
	require.Eventually(t, func() bool {
		current := sumMetric(t, mounts, "cache_fill_block_group")
		settled := current == totalFill && current > 0
		totalFill = current
		return settled
	}, 60*time.Second, 500*time.Millisecond, "prefetch never settled")

	t.Logf("prefetch amplification: solo=%.0f block groups, %d processes=%.0f block groups",
		soloFill, coreProcs, totalFill)
	require.LessOrEqual(t, totalFill, soloFill*1.5,
		"the per-blob prefetch lock should keep all but one process from refetching")
}

// TestCoreSharedBlobUsesOneCacheEntry checks that two images referencing
// the same blob converge on one set of cache files, which is what makes a node
// running many images cheap.
func TestCacheSharingSharedBlobUsesOneCacheEntry(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)
	cacheDir := filepath.Join(root, "cache")

	image1 := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap1,
		blobDir:   fixture.blobDir,
		cacheDir:  cacheDir,
		mnt:       filepath.Join(root, "mnt1"),
	})
	image2 := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap2,
		blobDir:   fixture.blobDir,
		cacheDir:  cacheDir,
		mnt:       filepath.Join(root, "mnt2"),
	})

	// Touch every blob: file1 only exists in image1, file3 only in image2, and
	// shared.bin is served by the same blob in both.
	require.Equal(t, sha256Bytes(fixture.files["file1.bin"]),
		sha256File(t, filepath.Join(image1.mnt, "file1.bin")))
	require.Equal(t, sha256Bytes(fixture.files["file3.bin"]),
		sha256File(t, filepath.Join(image2.mnt, "file3.bin")))

	digests := readConcurrently(t, []*coreMount{image1, image2}, "shared.bin")
	want := sha256Bytes(fixture.files["shared.bin"])
	require.Equal(t, []string{want, want}, digests)

	// The cache is keyed by blob content, so the shared blob must not be
	// cached once per image.
	sharedKey := sha256File(t, fixture.blobB)
	require.FileExists(t, filepath.Join(cacheDir, sharedKey+".blob.data"))
	require.Len(t, cacheEntries(t, cacheDir, ".blob.data"), 3,
		"expected one cache entry per distinct blob (A, B, C)")
}

// TestCorePrefetchAndOnDemandConcurrent runs a prefetching process against
// an on-demand one on the same cache. Neither may deadlock and both must see
// correct data.
func TestCacheSharingPrefetchAndOnDemandConcurrent(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)
	cacheDir := filepath.Join(root, "cache")

	prefetcher := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap:    fixture.bootstrap1,
		blobDir:      fixture.blobDir,
		cacheDir:     cacheDir,
		mnt:          filepath.Join(root, "mnt-prefetch"),
		prefetch:     true,
		fullPrefetch: true,
	})
	reader := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap1,
		blobDir:   fixture.blobDir,
		cacheDir:  cacheDir,
		mnt:       filepath.Join(root, "mnt-ondemand"),
	})

	digests := readConcurrently(t, []*coreMount{prefetcher, reader}, "shared.bin")
	want := sha256Bytes(fixture.files["shared.bin"])
	require.Equal(t, []string{want, want}, digests)

	// Re-read once the prefetch has had time to finish, covering the handover
	// from "filled by my own read" to "filled by the other process".
	require.Eventually(t, func() bool {
		return prefetcher.metrics(t)["cache_fill_block_group"] > 0
	}, 60*time.Second, 200*time.Millisecond, "prefetch never made progress")
	require.Equal(t, want, sha256File(t, filepath.Join(reader.mnt, "shared.bin")))
}

// TestCoreSurvivesPeerCrash kills one process mid-flight; the survivors
// must still complete their reads. Once per-block-group locks land this also covers
// a dead lock holder being taken over.
func TestCacheSharingSurvivesPeerCrash(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)
	cacheDir := filepath.Join(root, "cache")

	victim := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap:    fixture.bootstrap1,
		blobDir:      fixture.blobDir,
		cacheDir:     cacheDir,
		mnt:          filepath.Join(root, "mnt-victim"),
		prefetch:     true,
		fullPrefetch: true,
	})
	survivor := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap1,
		blobDir:   fixture.blobDir,
		cacheDir:  cacheDir,
		mnt:       filepath.Join(root, "mnt-survivor"),
	})

	victim.kill(t)

	done := make(chan string, 1)
	go func() {
		data, err := os.ReadFile(filepath.Join(survivor.mnt, "shared.bin"))
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- sha256Bytes(data)
	}()

	select {
	case got := <-done:
		require.Equal(t, sha256Bytes(fixture.files["shared.bin"]), got)
	case <-time.After(60 * time.Second):
		require.FailNow(t, "survivor blocked after a peer crashed")
	}
}

// TestCoreStaleGroupmapKeepsInode deletes the cached blob data behind a
// live mount. The readiness bitmap has to be reset, but every process must end
// up on the same bitmap file: if the reset swaps the inode, a live process
// keeps publishing readiness that newcomers can never see.
func TestCacheSharingStaleBlockGroupMapKeepsInode(t *testing.T) {
	skipUnlessRoot(t)

	root := t.TempDir()
	nydusBin := mustLookupExecutable(t, "nydus")
	fixture := buildCoreFixture(t, nydusBin, root)
	cacheDir := filepath.Join(root, "cache")

	first := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap1,
		blobDir:   fixture.blobDir,
		cacheDir:  cacheDir,
		mnt:       filepath.Join(root, "mnt1"),
	})
	require.Equal(t, sha256Bytes(fixture.files["shared.bin"]),
		sha256File(t, filepath.Join(first.mnt, "shared.bin")))

	sharedKey := sha256File(t, fixture.blobB)
	blockGroupMap := filepath.Join(cacheDir, sharedKey+".group.map")
	blobData := filepath.Join(cacheDir, sharedKey+".blob.data")
	require.FileExists(t, blockGroupMap)
	require.FileExists(t, blobData)
	before := cacheFileInode(t, blockGroupMap)

	// Simulate an external reclaimer that removes only the data file while the
	// first mount is still running.
	require.NoError(t, os.Remove(blobData))

	second := startCoreMount(t, nydusBin, coreMountOption{
		bootstrap: fixture.bootstrap1,
		blobDir:   fixture.blobDir,
		cacheDir:  cacheDir,
		mnt:       filepath.Join(root, "mnt2"),
	})
	require.Equal(t, sha256Bytes(fixture.files["shared.bin"]),
		sha256File(t, filepath.Join(second.mnt, "shared.bin")))

	after := cacheFileInode(t, blockGroupMap)
	t.Logf("block group map inode before=%d after=%d", before, after)

	// The bitmap is reset in place, so both processes keep observing the same
	// file. Replacing it would split them onto separate inodes and each would
	// publish readiness the other can never see.
	require.Equal(t, before, after,
		"the stale block group map must be reset in place, not replaced")
}
