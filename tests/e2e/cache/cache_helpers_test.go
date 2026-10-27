// Package cache runs several FUSE daemons on one cache directory: they must
// share fills, survive each other's crashes, and never serve wrong bytes from
// a cache that was damaged, deleted or locked behind their back.
package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"golang.org/x/sys/unix"
)

// procs is how many daemons contend on one cache: enough to show duplicate
// work without making the suite heavy.
const procs = 4

// Cache files are named <blob id><suffix> (nydus-storage/src/cache/local.rs).
const (
	dataSuffix     = ".blob.data"
	mapSuffix      = ".group.map"
	prefetchSuffix = ".prefetch.lock"
)

// Group map layout (nydus-storage/src/chunk_group_map.rs): a header with the
// group count and the sticky ALL_READY state bit, then one ready bit per
// group.
const (
	mapCountOffset = 16
	mapStateOffset = 24
	mapAllReady    = 1
	mapHeaderSize  = 4096
)

// Per-daemon fill counters: groups fetched for a read, and for prefetch.
const (
	ondemandFill = "ondemand"
	prefetchFill = "prefetch"
)

// imageRoot is where TestMain lets the shared images be built.
var imageRoot string

// world is the shared fixture: three single-file layers A, B and C merged
// into image1 (A+B) and image2 (B+C), so B is one blob both images use.
// Distinct file names keep the overlay from shadowing anything.
type world struct {
	// keyX is layer X's blob id, which names its cache files.
	keyA, keyB, keyC string
	image1, image2   fixture.Image
	// data and want are each file's content and its SHA256.
	data map[string][]byte
	want map[string]string
}

var shared struct {
	sync.Mutex
	w *world
}

// setup checks the FUSE preconditions and returns the shared images, which
// every test only reads.
func setup(t *testing.T) *world {
	t.Helper()
	mount.FUSE{}.Require(t)
	shared.Lock()
	defer shared.Unlock()
	if shared.w == nil {
		// A fresh directory per attempt, so a failed build is retried clean.
		dir, err := os.MkdirTemp(imageRoot, "images-")
		if err != nil {
			t.Fatalf("create image dir: %v", err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", dir, err)
		}
		shared.w = buildWorld(t, dir)
	}
	return shared.w
}

func buildWorld(t env.TB, dir string) *world {
	t.Helper()
	// 4 KiB chunks in 64 KiB groups: shared.bin spans ~190 groups, so
	// duplicate or missing fills are visible in the counters.
	layout, err := fixture.LayoutByName("zstd-4k-group-64k")
	if err != nil {
		t.Fatalf("%v", err)
	}
	layers := []struct {
		file string
		size int
		seed uint64
	}{
		{"file1.bin", 1<<20 + 4096, 1},
		{"shared.bin", 12 << 20, 2},
		{"file3.bin", 1<<20 + 2048, 3},
	}
	w := &world{data: map[string][]byte{}, want: map[string]string{}}
	blobDir := filepath.Join(dir, "blobs")
	var blobs []string
	var trees [][]oracle.Entry
	for i, l := range layers {
		src := filepath.Join(dir, fmt.Sprintf("layer%d", i))
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatalf("create %s: %v", src, err)
		}
		data := deterministicBytes(l.size, l.seed)
		if err := os.WriteFile(filepath.Join(src, l.file), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", l.file, err)
		}
		w.data[l.file] = data
		w.want[l.file] = sha256Hex(data)
		blob, _ := fixture.BuildInto(t, blobDir, filepath.Join(dir, fmt.Sprintf("layer%d.bootstrap", i)), src, layout)
		blobs = append(blobs, blob)
		trees = append(trees, oracle.ScanSource(t, src))
	}
	merge := func(name string, lower, upper int) fixture.Image {
		bootstrap := filepath.Join(dir, name+".bootstrap")
		fixture.Run(t, env.Nydus(t), "merge", "--bootstrap", bootstrap, blobs[lower], blobs[upper])
		return fixture.Image{
			Name:      name,
			Layout:    layout,
			Bootstrap: bootstrap,
			BlobDir:   blobDir,
			Blobs:     []string{blobs[lower], blobs[upper]},
			Merged:    true,
			Want:      oracle.Overlay(trees[lower], trees[upper]),
		}
	}
	w.keyA, w.keyB, w.keyC = filepath.Base(blobs[0]), filepath.Base(blobs[1]), filepath.Base(blobs[2])
	w.image1 = merge("image1", 0, 1)
	w.image2 = merge("image2", 1, 2)
	return w
}

// deterministicBytes is incompressible-enough content that is stable across
// runs, so blob ids (and so cache keys) are reproducible.
func deterministicBytes(size int, seed uint64) []byte {
	out := make([]byte, size)
	state := seed*6364136223846793005 + 1442695040888963407
	for i := range out {
		state = state*6364136223846793005 + 1442695040888963407
		out[i] = byte(state >> 33)
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// newCache returns a fresh cache directory for the daemons of one test.
func newCache(t env.TB) string {
	t.Helper()
	return filepath.Join(env.WorkDir(t), "cache")
}

// mountOn serves img over cacheDir with the default config (local backend,
// no prefetch) changed by edits.
func mountOn(t env.TB, img fixture.Image, cacheDir string, edits ...func(*mount.Config)) *mount.Mounted {
	t.Helper()
	return mount.Mount(t, mount.FUSE{}, img, mount.Options{
		CacheDir: cacheDir,
		Config: func(c *mount.Config) {
			for _, edit := range edits {
				edit(c)
			}
		},
	})
}

// mountN starts n daemons of img on one cache.
func mountN(t env.TB, n int, img fixture.Image, cacheDir string, edits ...func(*mount.Config)) []*mount.Mounted {
	t.Helper()
	mounts := make([]*mount.Mounted, n)
	for i := range mounts {
		mounts[i] = mountOn(t, img, cacheDir, edits...)
	}
	return mounts
}

// prefetchAll warms every blob, not just priority ones: a plain merged image
// has none, so without it a prefetching daemon does no work.
func prefetchAll(c *mount.Config) { c.Prefetch = &mount.Prefetch{Scope: "all"} }

// verifyChecksums turns on per-group CRC32C checks of fetched data.
func verifyChecksums(c *mount.Config) { c.Storage.SkipVerifyChecksums = mount.Ptr(false) }

func fetchSize(n int64) func(*mount.Config) {
	return func(c *mount.Config) { c.Storage.FetchSize = mount.Ptr(n) }
}

// metric reads one counter of m. The apiserver comes up after the mount, so
// it is waited for first.
func metric(t env.TB, m *mount.Mounted, name string) float64 {
	t.Helper()
	m.Daemon.WaitFor(t, 30*time.Second, "apiserver", func() bool {
		_, err := m.API.Get("/metrics")
		return err == nil
	})
	return m.API.Metrics(t).Sum("nydus_cache_write_total", `type="`+name+`"`)
}

// sumMetric adds a counter across daemons, which is how the duplicate work
// of daemons sharing a cache shows up.
func sumMetric(t env.TB, mounts []*mount.Mounted, name string) float64 {
	t.Helper()
	var total float64
	for _, m := range mounts {
		total += metric(t, m, name)
	}
	return total
}

// settled polls sample until it is positive and unchanged for a second, the
// longest a prefetch lock waiter sleeps, and returns it.
func settled(t env.TB, what string, sample func() float64) float64 {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	last := -1.0
	for {
		cur := sample()
		if cur > 0 && cur == last {
			return cur
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never settled (last sample %v)", what, cur)
		}
		last = cur
		time.Sleep(time.Second)
	}
}

// waitAllReady polls until the group map of every key has latched ALL_READY.
func waitAllReady(t env.TB, cacheDir string, keys ...string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for _, key := range keys {
		path := cacheFile(cacheDir, key, mapSuffix)
		for !allReady(path) {
			if time.Now().After(deadline) {
				t.Fatalf("%s never became all ready", path)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func allReady(mapPath string) bool {
	f, err := os.Open(mapPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var state [4]byte
	if _, err := f.ReadAt(state[:], mapStateOffset); err != nil {
		return false
	}
	return binary.LittleEndian.Uint32(state[:])&mapAllReady != 0
}

// readSum hashes path. The file's page cache is dropped first so the read
// reaches the daemon rather than the kernel's copy of an earlier read.
func readSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readAt reads n bytes of path at off, past the page cache like readSum.
func readAt(path string, off int64, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	_ = unix.Fadvise(int(f.Fd()), off, int64(n), unix.FADV_DONTNEED)
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, off)
	if err != nil && (!errors.Is(err, io.EOF) || got == 0) {
		return nil, err
	}
	return buf[:got], nil
}

// mustRead requires a read of path to return the right bytes.
func mustRead(t env.TB, path, want string) {
	t.Helper()
	got, err := readSum(path)
	switch {
	case err != nil:
		t.Errorf("read %s: %v", path, err)
	case got != want:
		t.Errorf("read %s returned wrong bytes: sha256 %s, want %s", path, got, want)
	}
}

// checkRead judges a read of a damaged cache: failing is allowed, wrong bytes
// never are.
func checkRead(t env.TB, path, want string) {
	t.Helper()
	got, err := readSum(path)
	switch {
	case err != nil:
		t.Logf("read %s failed, which is allowed: %v", path, err)
	case got != want:
		t.Errorf("read %s returned wrong bytes: sha256 %s, want %s", path, got, want)
	}
}

// mustReadAt requires n bytes of path at off to match data.
func mustReadAt(t env.TB, path string, off int64, n int, data []byte) {
	t.Helper()
	got, err := readAt(path, off, n)
	switch {
	case err != nil:
		t.Errorf("read %s at %d: %v", path, off, err)
	case !bytes.Equal(got, data[off:off+int64(len(got))]) || len(got) != n:
		t.Errorf("read %s at %d returned wrong bytes", path, off)
	}
}

type readResult struct {
	sum string
	err error
}

// readConcurrently reads every path at once, so the daemons race on a cold
// cache instead of warming it for each other in turn.
func readConcurrently(paths []string) []readResult {
	start := make(chan struct{})
	results := make([]readResult, len(paths))
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i].sum, results[i].err = readSum(path)
		}()
	}
	close(start)
	wg.Wait()
	return results
}

// mustReadConcurrently has every mount read rel at once and requires each
// read to return the right bytes.
func mustReadConcurrently(t env.TB, mounts []*mount.Mounted, rel, want string) {
	t.Helper()
	paths := make([]string, len(mounts))
	for i, m := range mounts {
		paths[i] = m.Path(rel)
	}
	for i, r := range readConcurrently(paths) {
		switch {
		case r.err != nil:
			t.Errorf("daemon %d: read %s: %v", i, rel, r.err)
		case r.sum != want:
			t.Errorf("daemon %d: read %s returned wrong bytes: sha256 %s, want %s", i, rel, r.sum, want)
		}
	}
}

func cacheFile(cacheDir, key, suffix string) string {
	return filepath.Join(cacheDir, key+suffix)
}

// inode identifies a cache file across daemons.
func inode(t env.TB, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Ino
}

// flipData flips one byte in every 64 KiB of a cache data file that holds
// data, i.e. in every chunk group that was filled, and returns how many.
func flipData(t env.TB, path string) int {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	fd := int(f.Fd())
	flipped := 0
	for off := int64(0); off < st.Size(); {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		if err != nil {
			t.Fatalf("SEEK_DATA %s: %v", path, err)
		}
		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil {
			t.Fatalf("SEEK_HOLE %s: %v", path, err)
		}
		for p := data; p < hole; p += 64 << 10 {
			var b [1]byte
			if _, err := f.ReadAt(b[:], p); err != nil {
				t.Fatalf("read %s at %d: %v", path, p, err)
			}
			b[0] ^= 0xff
			if _, err := f.WriteAt(b[:], p); err != nil {
				t.Fatalf("write %s at %d: %v", path, p, err)
			}
			flipped++
		}
		off = hole
	}
	return flipped
}

// forgeReady sets every ready bit of a group map and returns how many groups
// were not ready, i.e. now claim bytes the data file never got.
func forgeReady(t env.TB, path string) int {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var hdr [4]byte
	if _, err := f.ReadAt(hdr[:], mapCountOffset); err != nil {
		t.Fatalf("read %s header: %v", path, err)
	}
	count := int(binary.LittleEndian.Uint32(hdr[:]))
	bitmap := make([]byte, (count+7)/8)
	if _, err := f.ReadAt(bitmap, mapHeaderSize); err != nil {
		t.Fatalf("read %s bitmap: %v", path, err)
	}
	forged := 0
	for i := 0; i < count; i++ {
		if mask := byte(1) << (i % 8); bitmap[i/8]&mask == 0 {
			bitmap[i/8] |= mask
			forged++
		}
	}
	if _, err := f.WriteAt(bitmap, mapHeaderSize); err != nil {
		t.Fatalf("write %s bitmap: %v", path, err)
	}
	return forged
}

// holdFlock takes flock(LOCK_EX) on path, creating it, as a peer daemon
// resetting a group map or prefetching a blob would. The returned release is
// idempotent and also runs at cleanup.
func holdFlock(t env.TB, path string) func() {
	t.Helper()
	f := openLockFile(t, path)
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		t.Fatalf("flock %s: %v", path, err)
	}
	return releaser(t, f)
}

// holdOFD takes an open file description write lock over all of path: the
// lock a daemon holds on group map bytes while it fetches those groups.
func holdOFD(t env.TB, path string) func() {
	t.Helper()
	f := openLockFile(t, path)
	lk := unix.Flock_t{Type: unix.F_WRLCK}
	if err := unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lk); err != nil {
		_ = f.Close()
		t.Fatalf("OFD lock %s: %v", path, err)
	}
	return releaser(t, f)
}

func openLockFile(t env.TB, path string) *os.File {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return f
}

// releaser drops a lock by closing its only descriptor.
func releaser(t env.TB, f *os.File) func() {
	var once sync.Once
	release := func() { once.Do(func() { _ = f.Close() }) }
	t.Cleanup(release)
	return release
}
