package soak

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	readerCount    = 16
	maxReadSize    = 256 << 10
	warmupDuration = 5 * time.Second
	settleTimeout  = 20 * time.Second
	stopTimeout    = 10 * time.Second

	fdSlack     = 4
	threadSlack = 4
)

func TestLeak(t *testing.T) {
	t.Parallel()
	settings := loadSettings(t)
	img := fixture.Get(t, "zstd-4k")

	for _, a := range []mount.Adapter{mount.FUSE{}, mount.Fileio{}} {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			settings.leak(t, a, img, mount.Options{}, nil)
		})
	}
}

func (s settings) leak(t *testing.T, a mount.Adapter, img fixture.Image, opts mount.Options, ready func(*mount.Mounted)) {
	root := filepath.Dir(env.WorkDir(t))
	files := soakFiles(t, img)
	m := mount.Mount(t, a, img, opts)
	pid := m.Daemon.Pid()

	start := time.Now()
	seed := uint64(start.UnixNano())
	t.Logf("soaking %d files with seed %d", len(files), seed)
	load := startSoak(m, img.Source, files, seed)
	defer load.halt()

	if ready != nil {
		ready(m)
	}

	time.Sleep(warmupDuration)
	start = time.Now().Add(-warmupDuration)
	base := sample(t, pid)
	peakRSS := base.RSS

	waitUntil := func(deadline time.Time) {
		for time.Now().Before(deadline) {
			peakRSS = max(peakRSS, sample(t, pid).RSS)
			time.Sleep(min(time.Second, time.Until(deadline)))
		}
	}

	var kids []int
	probe := probeFile(t, files)

	for cycle := range s.cycles {
		waitUntil(start.Add(warmupDuration + (s.duration-warmupDuration)*time.Duration(cycle)/time.Duration(s.cycles)))
		c := mount.Mount(t, a, img, opts)
		assert.NoError(t, check(c.Root, img.Source, probe.rel, 0, probe.size))
		kids = append(kids, proc.Children(c.Daemon.Pid())...)
		c.Unmount()

		assert.False(t, c.Daemon.Killed())
		mount.ExpectNoMounts(t, c.Dir)
		peakRSS = max(peakRSS, sample(t, pid).RSS)
	}

	t.Logf("%d mount cycles took %s", s.cycles, time.Since(start)-warmupDuration)

	waitUntil(start.Add(s.duration))
	load.finish(t)

	end := settle(t, pid, base)
	peakRSS = max(peakRSS, end.RSS)

	if s.rssBytes > 0 {
		assert.LessOrEqual(t, peakRSS-base.RSS, s.rssBytes)
	}

	t.Logf("daemon at baseline: %+v; at the end: %+v", base, end)

	if base.RSS > 0 && float64(end.RSS-base.RSS) > 0.10*float64(base.RSS) {
		t.Logf("WARNING: RSS grew from %dMiB to %dMiB", base.RSS>>20, end.RSS>>20)
	}

	kids = append(kids, proc.Children(pid)...)
	m.Unmount()
	assert.False(t, m.Daemon.Killed())
	mount.ExpectNoMounts(t, root)
	proc.ExpectGone(t, kids, stopTimeout)
}

type soakFile struct {
	rel  string
	size int64
}

func soakFiles(t *testing.T, img fixture.Image) []soakFile {
	t.Helper()
	var out []soakFile

	for _, e := range img.Want {
		rel := string(e.Path)

		if e.Type != fstest.TypeReg || e.Size == 0 || e.Size > 64<<20 {
			continue
		}

		if strings.HasPrefix(rel, "data/") || strings.HasPrefix(rel, "holes/") {
			out = append(out, soakFile{rel: rel, size: e.Size})
		}
	}

	if !assert.NotEmpty(t, out) {
		t.FailNow()
	}

	return out
}

func probeFile(t *testing.T, files []soakFile) soakFile {
	t.Helper()
	for _, f := range files {
		if f.rel == "data/size/00065537" {
			return f
		}
	}

	t.Fatalf("no probe file among the soaked files")

	return soakFile{}
}

type soak struct {
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
	reads    atomic.Int64
	bytes    atomic.Int64
	mu       sync.Mutex
	failed   int
	first    []string
}

func startSoak(m *mount.Mounted, src string, files []soakFile, seed uint64) *soak {
	s := &soak{stop: make(chan struct{}), done: make(chan struct{})}
	var wg sync.WaitGroup

	for i := range readerCount {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(seed, uint64(i)))

			for !s.stopped() {
				f := files[rng.IntN(len(files))]
				off := rng.Int64N(f.size)

				n := min(int64(1+rng.IntN(maxReadSize)), f.size-off)
				if err := check(m.Root, src, f.rel, off, n); err != nil {
					s.fail(err)
					continue
				}

				s.reads.Add(1)
				s.bytes.Add(n)
			}
		})
	}

	export := filepath.Join(m.Dir, "export")
	if _, err := os.Stat(export); err == nil {
		wg.Go(func() {
			for !s.stopped() {
				dropCaches(export)
				time.Sleep(250 * time.Millisecond)
			}
		})
	}

	go func() { wg.Wait(); close(s.done) }()

	return s
}

func (s *soak) stopped() bool {
	select {
	case <-s.stop:
		return true

	default:
		return false
	}
}

func (s *soak) halt() { s.stopOnce.Do(func() { close(s.stop) }) }

func (s *soak) finish(t *testing.T) {
	t.Helper()
	s.halt()

	select {
	case <-s.done:

	case <-time.After(stopTimeout):
		t.Fatalf("a reader is still blocked %s after stop: reads hang", stopTimeout)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	t.Logf("%d reads, %dMiB verified", s.reads.Load(), s.bytes.Load()>>20)
	assert.NotZero(t, s.reads.Load())
	assert.Zero(t, s.failed)
	assert.Empty(t, s.first)
}

func (s *soak) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed++

	if len(s.first) < 8 {
		s.first = append(s.first, err.Error())
	}
}

func check(mnt, src, rel string, off, n int64) error {
	got, err := fstest.ReadAtCold(filepath.Join(mnt, rel), off, n)
	if err != nil {
		return fmt.Errorf("read %s at %d+%d: %w", rel, off, n, err)
	}

	want, err := fstest.ReadAt(filepath.Join(src, rel), off, n)
	if err != nil {
		return fmt.Errorf("read source %s at %d+%d: %w", rel, off, n, err)
	}
	if int64(len(got)) < n || !bytes.Equal(got, want) {
		return fmt.Errorf("%s at %d+%d: wrong bytes", rel, off, n)
	}

	return nil
}

func dropCaches(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}

		if f, err := os.Open(filepath.Join(dir, e.Name())); err == nil {
			_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
			_ = f.Close()
		}
	}
}

func sample(t *testing.T, pid int) proc.Sample {
	t.Helper()
	s, err := proc.Of(pid)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return s
}

func settle(t *testing.T, pid int, base proc.Sample) proc.Sample {
	t.Helper()
	var s proc.Sample
	if !assert.Eventually(t, func() bool {
		cur, err := proc.Of(pid)
		if err != nil {
			return false
		}

		s = cur

		return s.FDs <= base.FDs+fdSlack && s.Threads <= base.Threads+threadSlack
	}, settleTimeout, 200*time.Millisecond) {
		t.FailNow()
	}

	return s
}

func TestRemote(t *testing.T) {
	t.Parallel()
	settings := loadSettings(t)
	img := fixture.Get(t, "zstd-4k")

	for _, a := range []mount.Adapter{mount.FUSE{}, mount.Fileio{}} {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			reg := registry.Start(t)
			reg.PushBlobs(t, "soak", img.Blobs)
			reg.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable, Times: 1})

			opts := mount.Options{
				CacheDir: filepath.Join(env.WorkDir(t), "shared-cache"),
				Config: func(c *mount.Config) {
					c.Backend = mount.RegistryBackend(mount.RegistryConfig{
						Addr: reg.URL, Repository: "soak",
						HTTP: &mount.HTTPConfig{MaxRetries: mount.Ptr(3)},
					})

					c.Prefetch = &mount.PrefetchConfig{Scope: "all", RetryInterval: "100ms"}
				},
			}

			settings.leak(t, a, img, opts, func(m *mount.Mounted) {
				m.Daemon.WaitFor(t, time.Minute, "prefetch completion before resource baseline", func() bool {
					body, err := m.API.Get("/metrics")
					if err != nil {
						return false
					}

					metrics := mount.ParseMetrics(string(body))

					return metrics.Sum("nydus_storage_prefetch_task_total") > 0 && metrics.Has("nydus_cache_bytes") &&
						metrics.Sum("nydus_cache_bytes", `status="uncached"`) == 0
				})
			})

			if !assert.Positive(t, reg.Faults.Hits()) {
				t.FailNow()
			}

			assert.Greater(t, len(reg.Faults.Requests()), 1)
		})
	}
}

type settings struct {
	duration time.Duration
	cycles   int
	rssBytes int64
}

func loadSettings(t *testing.T) settings {
	t.Helper()
	s := settings{
		duration: env.Duration(t, "NYDUS_E2E_SOAK_DURATION", 30*time.Second),
		cycles:   env.Int(t, "NYDUS_E2E_SOAK_CYCLES", 6),
		rssBytes: int64(env.Int(t, "NYDUS_E2E_SOAK_RSS_MIB", 0)) << 20,
	}

	if !assert.GreaterOrEqual(t, s.duration, 10*time.Second) || !assert.LessOrEqual(t, s.duration, 24*time.Hour) {
		t.FailNow()
	}
	if !assert.GreaterOrEqual(t, s.cycles, 1) || !assert.LessOrEqual(t, s.cycles, 100000) {
		t.FailNow()
	}
	if !assert.GreaterOrEqual(t, s.rssBytes, int64(0)) || !assert.LessOrEqual(t, s.rssBytes, int64(1)<<40) {
		t.FailNow()
	}

	return s
}
