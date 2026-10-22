package e2e

// Cross-process tests for the shared blob cache. Several `nydus fuse`
// processes are pointed at one --cache-dir, which is the state they contend
// on, and the assertions read back the cache directory and each process's
// Prometheus metrics.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
)

// contendingProcesses is how many processes contend on one cache directory.
// Four is enough to show duplicate work without making the suite heavy.
const contendingProcesses = 4

// fixtureChunkSize is the chunk size the fixture images are built with.
const fixtureChunkSize = 4096

// fuseMount is a running `nydus fuse` process together with the Unix
// socket its metrics are served on.
type fuseMount struct {
	// mountpoint is where the image is mounted.
	mountpoint string

	// apiserver is the Unix socket the daemon serves metrics on.
	apiserver string

	// cmd is the running process.
	cmd *exec.Cmd
}

// fuseMountOption describes one `nydus fuse` process to start.
type fuseMountOption struct {
	// bootstrap is the image to serve.
	bootstrap string

	// blobDir holds the image's blobs.
	blobDir string

	// cacheDir is the shared chunk cache.
	cacheDir string

	// mountpoint is where to mount the image.
	mountpoint string

	// prefetch turns on background prefetch.
	prefetch bool

	// prefetchAll warms every blob rather than only the priority ones. Plain
	// merged images have no priority blobs, so without this a prefetching
	// mount does no work at all.
	prefetchAll bool
}

// startFuseMount mounts an image and waits until both the mountpoint and
// the metrics endpoint answer.
func startFuseMount(t *testing.T, option fuseMountOption) *fuseMount {
	t.Helper()
	util.Unmount(option.mountpoint)
	assert.NoError(t, os.MkdirAll(option.mountpoint, 0o755))
	assert.NoError(t, os.MkdirAll(option.cacheDir, 0o755))
	dir := t.TempDir()
	apiserver := filepath.Join(dir, "api.sock")

	args := []string{
		"fuse",
		"--bootstrap", option.bootstrap,
		"--blob-dir", option.blobDir,
		"--cache-dir", option.cacheDir,
		"--mountpoint", option.mountpoint,
		"--apiserver", "unix://" + apiserver,
	}
	if option.prefetch {
		args = append(args, "--prefetch")
	}

	// All-blob prefetch has no command line flag of its own, so it needs a
	// storage config.
	if option.prefetchAll {
		configPath := filepath.Join(dir, "storage.yaml")
		util.WriteLocalBackendConfig(t, configPath, option.blobDir, option.cacheDir, "all")
		args = append(args, "--config", configPath)
	}

	// Start the process and wait for the mount and the metrics endpoint. A
	// daemon that never answers stops the test here, before its readers
	// block on the mount for a minute and fail for the wrong reason.
	cmd := exec.Command(nydusBin, args...)
	t.Cleanup(util.MountFuse(t, cmd, option.mountpoint, "nydus fuse"))
	util.WaitAPIServer(t, apiserver)
	if t.Failed() {
		t.FailNow()
	}

	return &fuseMount{mountpoint: option.mountpoint, apiserver: apiserver, cmd: cmd}
}

// kill terminates the process without giving it a chance to clean up, standing
// in for a crash.
func (m *fuseMount) kill(t *testing.T) {
	t.Helper()
	if !assert.NotNil(t, m.cmd.Process) {
		return
	}

	assert.NoError(t, m.cmd.Process.Kill())
	_, _ = m.cmd.Process.Wait()
	util.Unmount(m.mountpoint)
}

// fills returns how many chunk groups the process wrote into the cache for
// reads of kind, `ondemand` or `prefetch`.
func (m *fuseMount) fills(t *testing.T, kind string) float64 {
	t.Helper()
	return util.SumMetric(util.FetchMetrics(t, m.apiserver), "nydus_cache_write_total", `type="`+kind+`"`)
}

// sharedBlobFixture is two images sharing one blob, so the tests can tell
// per-image cache state apart from per-blob cache state.
//
//	image1 = blobA + blobB
//	image2 =         blobB + blobC
type sharedBlobFixture struct {
	// blobDir holds blobA, blobB and blobC.
	blobDir string

	// blobA is the blob holding file1.bin.
	blobA string

	// blobB is the blob holding shared.bin, referenced by both images.
	blobB string

	// blobC is the blob holding file3.bin.
	blobC string

	// bootstrap1 is image1, blobA merged with blobB.
	bootstrap1 string

	// bootstrap2 is image2, blobB merged with blobC.
	bootstrap2 string

	// files is the content of every file by name: file1.bin lives in blobA,
	// shared.bin in blobB, file3.bin in blobC.
	files map[string][]byte
}

// newSharedBlobFixture builds the three blobs and the two merged images under
// workDir.
func newSharedBlobFixture(t *testing.T, workDir string) *sharedBlobFixture {
	t.Helper()

	// Deterministic content keeps blob digests, and therefore cache keys,
	// reproducible across runs. shared.bin is large enough to span several
	// chunk groups: with only one chunk group per blob a per-process refetch
	// would barely register in the fill counter.
	files := map[string][]byte{
		"file1.bin":  util.RandomBytes(1<<20+4096, 1),
		"shared.bin": util.RandomBytes(12<<20, 2),
		"file3.bin":  util.RandomBytes(1<<20+2048, 3),
	}
	corpus.NewCorpus(t, filepath.Join(workDir, "corpusA")).CreateFile(t, "file1.bin", files["file1.bin"])
	corpus.NewCorpus(t, filepath.Join(workDir, "corpusB")).CreateFile(t, "shared.bin", files["shared.bin"])
	corpus.NewCorpus(t, filepath.Join(workDir, "corpusC")).CreateFile(t, "file3.bin", files["file3.bin"])

	// Distinct file names across the corpora keep overlay merge from shadowing
	// anything, so every blob stays reachable in the merged images.
	blobDir := filepath.Join(workDir, "blobs")
	blobA := util.BuildImage(t, nydusBin, "", blobDir, filepath.Join(workDir, "corpusA"), fixtureChunkSize)
	blobB := util.BuildImage(t, nydusBin, "", blobDir, filepath.Join(workDir, "corpusB"), fixtureChunkSize)
	blobC := util.BuildImage(t, nydusBin, "", blobDir, filepath.Join(workDir, "corpusC"), fixtureChunkSize)
	bootstrap1 := filepath.Join(workDir, "image1.boot")
	bootstrap2 := filepath.Join(workDir, "image2.boot")
	util.MergeBootstrap(t, nydusBin, bootstrap1, blobA, blobB)
	util.MergeBootstrap(t, nydusBin, bootstrap2, blobB, blobC)

	return &sharedBlobFixture{
		blobDir:    blobDir,
		blobA:      blobA,
		blobB:      blobB,
		blobC:      blobC,
		bootstrap1: bootstrap1,
		bootstrap2: bootstrap2,
		files:      files,
	}
}

// readConcurrently has every mount read the same relative path at once, so the
// processes genuinely race on a cold cache instead of warming it for each
// other in turn, and returns the digest each mount read.
func readConcurrently(t *testing.T, mounts []*fuseMount, name string) []string {
	t.Helper()
	start := make(chan struct{})
	digests := make([]string, len(mounts))
	errs := make([]error, len(mounts))

	var wg sync.WaitGroup
	for i, m := range mounts {
		wg.Go(func() {
			<-start
			data, err := os.ReadFile(filepath.Join(m.mountpoint, name))
			if err != nil {
				errs[i] = err
				return
			}
			digests[i] = digest.FromBytes(data).Encoded()
		})
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "mount %d failed to read %s", i, name)
	}

	return digests
}

// sumFills adds the backend fills of kind across every mount, which is how
// the duplicate work of processes sharing a cache directory shows up.
func sumFills(t *testing.T, mounts []*fuseMount, kind string) float64 {
	t.Helper()
	var total float64
	for _, m := range mounts {
		total += m.fills(t, kind)
	}

	return total
}

// waitFillsSettled polls the backend fills of kind summed across every mount
// until they are non-zero and unchanged across three consecutive samples,
// like util.WaitMetricSettled does for one daemon, and returns the sum. The
// per-blob prefetch lock leaves every mount but the winner at zero, so no
// single daemon's metric can stand in for the sum.
func waitFillsSettled(t *testing.T, mounts []*fuseMount, kind string) float64 {
	t.Helper()
	return util.WaitSettled(t, kind+" fills", func() (float64, error) { return sumFills(t, mounts, kind), nil })
}

// TestCacheSharingConcurrentColdReadIsConsistent covers the baseline
// guarantee: however much duplicate work the processes do, they all observe
// the same bytes and the cache never serves a torn chunk group.
func TestCacheSharingConcurrentColdReadIsConsistent(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)
	cacheDir := filepath.Join(workDir, "cache")

	// Start every process on one cold cache.
	mounts := make([]*fuseMount, contendingProcesses)
	for i := range mounts {
		mounts[i] = startFuseMount(t, fuseMountOption{
			bootstrap:  fixture.bootstrap1,
			blobDir:    fixture.blobDir,
			cacheDir:   cacheDir,
			mountpoint: filepath.Join(workDir, fmt.Sprintf("mnt%d", i)),
		})
	}

	// Every process must read the same bytes.
	digests := readConcurrently(t, mounts, "shared.bin")
	want := digest.FromBytes(fixture.files["shared.bin"]).Encoded()
	for i, got := range digests {
		assert.Equal(t, want, got, "mount %d read different bytes", i)
	}
}

// TestCacheSharingConcurrentColdReadAmplification measures how much duplicate
// fetching the processes do, calibrated against a single process doing the
// same read so the assertion does not depend on the blob's chunk group count.
func TestCacheSharingConcurrentColdReadAmplification(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)

	// Baseline: one process filling a cold cache on its own.
	soloCacheDir := filepath.Join(workDir, "cache-solo")
	solo := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap1,
		blobDir:    fixture.blobDir,
		cacheDir:   soloCacheDir,
		mountpoint: filepath.Join(workDir, "mnt-solo"),
	})
	readConcurrently(t, []*fuseMount{solo}, "shared.bin")
	soloFill := solo.fills(t, "ondemand")
	assert.Greater(soloFill, 1.0,
		"the read must span several chunk groups for the comparison below to mean anything")

	// Contended: the same read, from a cold cache, by several processes.
	sharedCacheDir := filepath.Join(workDir, "cache-shared")
	mounts := make([]*fuseMount, contendingProcesses)
	for i := range mounts {
		mounts[i] = startFuseMount(t, fuseMountOption{
			bootstrap:  fixture.bootstrap1,
			blobDir:    fixture.blobDir,
			cacheDir:   sharedCacheDir,
			mountpoint: filepath.Join(workDir, fmt.Sprintf("mnt-shared%d", i)),
		})
	}
	readConcurrently(t, mounts, "shared.bin")
	totalFill := sumFills(t, mounts, "ondemand")
	t.Logf("cold read amplification: solo=%.0f chunk groups, %d processes=%.0f chunk groups (%.2fx)",
		soloFill, contendingProcesses, totalFill, totalFill/soloFill)

	// Whoever wins a chunk group's fetch right publishes it, and the processes
	// that waited find it ready instead of fetching it again, so the total
	// should match a single process doing the same read. One chunk group of
	// slack covers a filesystem that cannot provide the lock and falls back to
	// refetching.
	assert.LessOrEqual(totalFill, soloFill+1,
		"concurrent cold reads should not refetch the same chunk groups per process")
}

// TestCacheSharingConcurrentPrefetchDeduplicates checks the path that already
// has cross-process exclusion: the per-blob prefetch lock should keep all but
// one process from streaming the blob.
func TestCacheSharingConcurrentPrefetchDeduplicates(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)

	// Baseline: one process prefetching a cold cache on its own. Prefetch runs
	// in the background, so wait for it to settle rather than sampling a
	// partial total.
	soloCacheDir := filepath.Join(workDir, "cache-solo")
	solo := startFuseMount(t, fuseMountOption{
		bootstrap:   fixture.bootstrap1,
		blobDir:     fixture.blobDir,
		cacheDir:    soloCacheDir,
		mountpoint:  filepath.Join(workDir, "mnt-solo"),
		prefetch:    true,
		prefetchAll: true,
	})
	soloFill := util.WaitMetricSettled(t, solo.apiserver, "nydus_cache_write_total", `type="prefetch"`)

	// Contended: several processes prefetching one cold cache.
	sharedCacheDir := filepath.Join(workDir, "cache-shared")
	mounts := make([]*fuseMount, contendingProcesses)
	for i := range mounts {
		mounts[i] = startFuseMount(t, fuseMountOption{
			bootstrap:   fixture.bootstrap1,
			blobDir:     fixture.blobDir,
			cacheDir:    sharedCacheDir,
			mountpoint:  filepath.Join(workDir, fmt.Sprintf("mnt-shared%d", i)),
			prefetch:    true,
			prefetchAll: true,
		})
	}
	totalFill := waitFillsSettled(t, mounts, "prefetch")

	t.Logf("prefetch amplification: solo=%.0f chunk groups, %d processes=%.0f chunk groups",
		soloFill, contendingProcesses, totalFill)
	assert.LessOrEqual(totalFill, soloFill*1.5,
		"the per-blob prefetch lock should keep all but one process from refetching")
}

// TestCacheSharingSharedBlobUsesOneCacheEntry checks that two images
// referencing the same blob converge on one set of cache files, which is what
// makes a node running many images cheap.
func TestCacheSharingSharedBlobUsesOneCacheEntry(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)
	cacheDir := filepath.Join(workDir, "cache")

	// Serve both images from one cache.
	image1 := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap1,
		blobDir:    fixture.blobDir,
		cacheDir:   cacheDir,
		mountpoint: filepath.Join(workDir, "mnt1"),
	})
	image2 := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap2,
		blobDir:    fixture.blobDir,
		cacheDir:   cacheDir,
		mountpoint: filepath.Join(workDir, "mnt2"),
	})

	// Touch every blob: file1 only exists in image1, file3 only in image2, and
	// shared.bin is served by the same blob in both.
	assert.Equal(digest.FromBytes(fixture.files["file1.bin"]).Encoded(),
		util.Sha256File(t, filepath.Join(image1.mountpoint, "file1.bin")))
	assert.Equal(digest.FromBytes(fixture.files["file3.bin"]).Encoded(),
		util.Sha256File(t, filepath.Join(image2.mountpoint, "file3.bin")))
	digests := readConcurrently(t, []*fuseMount{image1, image2}, "shared.bin")
	want := digest.FromBytes(fixture.files["shared.bin"]).Encoded()
	assert.Equal([]string{want, want}, digests)

	// The cache is keyed by blob content, so the shared blob must not be
	// cached once per image.
	sharedBlobKey := util.Sha256File(t, fixture.blobB)
	assert.FileExists(filepath.Join(cacheDir, sharedBlobKey+".blob.data"))
	entries, err := filepath.Glob(filepath.Join(cacheDir, "*.blob.data"))
	assert.NoError(err)
	assert.Len(entries, 3, "expected one cache entry per distinct blob (A, B, C)")
}

// TestCacheSharingPrefetchAndOnDemandConcurrent runs a prefetching process
// against an on-demand one on the same cache. Neither may deadlock and both
// must see correct data.
func TestCacheSharingPrefetchAndOnDemandConcurrent(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)
	cacheDir := filepath.Join(workDir, "cache")

	// One prefetching and one on-demand process on one cache.
	prefetcher := startFuseMount(t, fuseMountOption{
		bootstrap:   fixture.bootstrap1,
		blobDir:     fixture.blobDir,
		cacheDir:    cacheDir,
		mountpoint:  filepath.Join(workDir, "mnt-prefetch"),
		prefetch:    true,
		prefetchAll: true,
	})
	onDemand := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap1,
		blobDir:    fixture.blobDir,
		cacheDir:   cacheDir,
		mountpoint: filepath.Join(workDir, "mnt-ondemand"),
	})

	// Both must read the same bytes while racing on the cold cache.
	digests := readConcurrently(t, []*fuseMount{prefetcher, onDemand}, "shared.bin")
	want := digest.FromBytes(fixture.files["shared.bin"]).Encoded()
	assert.Equal([]string{want, want}, digests)

	// Re-read once the prefetch has had time to finish, covering the handover
	// from "filled by my own read" to "filled by the other process".
	assert.Eventually(func() bool {
		return prefetcher.fills(t, "prefetch") > 0
	}, 60*time.Second, 200*time.Millisecond, "prefetch never made progress")
	assert.Equal(want, util.Sha256File(t, filepath.Join(onDemand.mountpoint, "shared.bin")))
}

// TestCacheSharingSurvivesPeerCrash kills one process mid-flight; the
// survivors must still complete their reads. Once per-chunk-group locks land
// this also covers a dead lock holder being taken over.
func TestCacheSharingSurvivesPeerCrash(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)
	cacheDir := filepath.Join(workDir, "cache")

	// A prefetching victim and an on-demand survivor on one cache.
	victim := startFuseMount(t, fuseMountOption{
		bootstrap:   fixture.bootstrap1,
		blobDir:     fixture.blobDir,
		cacheDir:    cacheDir,
		mountpoint:  filepath.Join(workDir, "mnt-victim"),
		prefetch:    true,
		prefetchAll: true,
	})
	survivor := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap1,
		blobDir:    fixture.blobDir,
		cacheDir:   cacheDir,
		mountpoint: filepath.Join(workDir, "mnt-survivor"),
	})

	// Crash the victim while its prefetch is in flight.
	victim.kill(t)

	// The survivor's read must finish with the right bytes.
	done := make(chan string, 1)
	go func() {
		data, err := os.ReadFile(filepath.Join(survivor.mountpoint, "shared.bin"))
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- digest.FromBytes(data).Encoded()
	}()
	select {
	case got := <-done:
		assert.Equal(digest.FromBytes(fixture.files["shared.bin"]).Encoded(), got)
	case <-time.After(60 * time.Second):
		assert.FailNow("survivor blocked after a peer crashed")
	}
}

// TestCacheSharingStaleGroupMapKeepsInode deletes the cached blob data behind
// a live mount. The readiness bitmap has to be reset, but every process must
// end up on the same bitmap file: if the reset swaps the inode, a live process
// keeps publishing readiness that newcomers can never see.
func TestCacheSharingStaleGroupMapKeepsInode(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	fixture := newSharedBlobFixture(t, workDir)
	cacheDir := filepath.Join(workDir, "cache")

	// Fill the cache from the first mount and note the group map's inode.
	first := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap1,
		blobDir:    fixture.blobDir,
		cacheDir:   cacheDir,
		mountpoint: filepath.Join(workDir, "mnt1"),
	})
	assert.Equal(digest.FromBytes(fixture.files["shared.bin"]).Encoded(),
		util.Sha256File(t, filepath.Join(first.mountpoint, "shared.bin")))
	sharedBlobKey := util.Sha256File(t, fixture.blobB)
	groupMap := filepath.Join(cacheDir, sharedBlobKey+".group.map")
	cacheData := filepath.Join(cacheDir, sharedBlobKey+".blob.data")
	assert.FileExists(groupMap)
	assert.FileExists(cacheData)
	inodeBefore := util.Inode(t, groupMap)

	// Simulate an external reclaimer that removes only the data file while the
	// first mount is still running, then read through a second mount.
	assert.NoError(os.Remove(cacheData))
	second := startFuseMount(t, fuseMountOption{
		bootstrap:  fixture.bootstrap1,
		blobDir:    fixture.blobDir,
		cacheDir:   cacheDir,
		mountpoint: filepath.Join(workDir, "mnt2"),
	})
	assert.Equal(digest.FromBytes(fixture.files["shared.bin"]).Encoded(),
		util.Sha256File(t, filepath.Join(second.mountpoint, "shared.bin")))

	// The bitmap is reset in place, so both processes keep observing the same
	// file. Replacing it would split them onto separate inodes and each would
	// publish readiness the other can never see.
	inodeAfter := util.Inode(t, groupMap)
	t.Logf("group map inode before=%d after=%d", inodeBefore, inodeAfter)
	assert.Equal(inodeBefore, inodeAfter,
		"the stale group map must be reset in place, not replaced")
}
