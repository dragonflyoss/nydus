// Package soak runs long parallel reads and mount cycles and checks that
// nothing leaks: daemon fds and threads, mounts, processes.
package soak

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/soakconfig"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	// warmFor is the part of the soak after which the baseline is taken:
	// thread pools and caches have grown to their working size by then.
	warmFor  = 5 * time.Second
	nReaders = 16
	maxRead  = 256 << 10

	// fdSlack and threadSlack absorb what a daemon may legitimately hold
	// open or spawn at one moment and not the next.
	fdSlack     = 4
	threadSlack = 4
	// settleTimeout bounds how long idle threads and fds get to go away.
	settleTimeout = 20 * time.Second
	// stopTimeout bounds how long a reader may stay in a read once stopped.
	stopTimeout = 10 * time.Second
)

// TestLeak soaks each adapter: 16 goroutines issue random reads for 30s,
// each checked against the source, while 20 more daemons of the same
// adapter mount, serve a read and unmount one after another. Afterwards the
// soaked daemon holds no more fds or threads than it did once warmed up,
// within a small slack; nothing is left mounted under the test's
// directories; no daemon or child process is left. RSS growth over 10% is
// reported; an explicitly configured warmed-RSS growth budget also gates.
func TestLeak(t *testing.T) {
	t.Parallel()
	settings, err := soakconfig.Parse(os.Getenv)
	require.NoError(t, err)
	img := fixture.Get(t, "zstd-4k")
	for _, a := range []mount.Adapter{mount.FUSE{}, mount.Fileio{}} {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			leak(t, a, img, settings, mount.Options{}, nil)
		})
	}
}

func leak(t *testing.T, a mount.Adapter, img fixture.Image, settings soakconfig.Settings, opts mount.Options, ready func(*mount.Mounted)) {
	// Every directory this test creates, mount.Mount's included, lives here.
	root := filepath.Dir(env.WorkDir(t))
	files := soakFiles(t, img)
	m := mount.Mount(t, a, img, opts)
	pid := m.Daemon.Pid()

	start := time.Now()
	seed := uint64(start.UnixNano())
	t.Logf("soaking %d files with seed %d", len(files), seed)
	s := startSoak(m, img.Source, files, seed)
	defer s.halt()
	if ready != nil {
		ready(m)
	}
	time.Sleep(warmFor)
	start = time.Now().Add(-warmFor)
	base := sample(t, pid)
	peakRSS := base.RSS
	waitUntil := func(deadline time.Time) {
		for time.Now().Before(deadline) {
			peakRSS = max(peakRSS, sample(t, pid).RSS)
			time.Sleep(min(time.Second, time.Until(deadline)))
		}
	}

	var cycled []*mount.Daemon
	var kids []int
	probe := probeFile(t, files)
	for cycle := range settings.Cycles {
		// Spread churn across the workload, rather than completing every
		// mount near startup and only reading for the rest of an hour.
		waitUntil(start.Add(warmFor + (settings.Duration-warmFor)*time.Duration(cycle)/time.Duration(settings.Cycles)))
		c := mount.Mount(t, a, img, opts)
		if err := check(c.Root, img.Source, probe.Rel, 0, make([]byte, probe.Size), make([]byte, probe.Size)); err != nil {
			t.Errorf("cycle mount: %v", err)
		}
		kids = append(kids, proc.Children(c.Daemon.Pid())...)
		c.Unmount()
		// Unmount ends in SIGKILL after a grace period, so the daemon is
		// always gone; what matters is whether it went by itself.
		if c.Daemon.Killed() {
			t.Errorf("%s %d had to be killed: it did not exit after SIGTERM", c.Daemon.Name, c.Daemon.Pid())
		}
		expectNoMounts(t, filepath.Dir(c.Root), c.Root)
		cycled = append(cycled, c.Daemon)
		peakRSS = max(peakRSS, sample(t, pid).RSS)
	}
	t.Logf("%d mount cycles took %s", settings.Cycles, time.Since(start)-warmFor)

	// Sample throughout the soak: a transient peak must not hide behind a
	// low final RSS. The budget is growth from the warmed baseline.
	waitUntil(start.Add(settings.Duration))
	s.finish(t)

	end := settle(t, pid, base)
	peakRSS = max(peakRSS, end.RSS)
	if settings.RSSBytes > 0 && peakRSS-base.RSS > settings.RSSBytes {
		t.Errorf("peak RSS growth %dMiB exceeds configured %dMiB budget", (peakRSS-base.RSS)>>20, settings.RSSBytes>>20)
	}
	t.Logf("daemon at baseline: %+v; at the end: %+v", base, end)
	if end.FDs > base.FDs+fdSlack {
		t.Errorf("fds grew from %d to %d", base.FDs, end.FDs)
	}
	if end.Threads > base.Threads+threadSlack {
		t.Errorf("threads grew from %d to %d", base.Threads, end.Threads)
	}
	if base.RSS > 0 && float64(end.RSS-base.RSS) > 0.10*float64(base.RSS) {
		t.Logf("WARNING: RSS grew from %dMiB to %dMiB", base.RSS>>20, end.RSS>>20)
	}

	kids = append(kids, proc.Children(pid)...)
	m.Unmount()
	if m.Daemon.Killed() {
		t.Errorf("%s had to be killed: it did not exit after SIGTERM", m.Daemon.Name)
	}
	expectNoMounts(t, root, m.Root)
	for _, d := range cycled {
		if d.Alive() {
			t.Errorf("cycled %s %d still running", d.Name, d.Pid())
		}
	}
	expectGone(t, kids)
}

// soakFile is a regular file the soak reads ranges of.
type soakFile struct {
	Rel  string
	Size int64
}

// soakFiles lists the non-empty regular files of img's plain-content and
// sparse corners, without the multi-GiB ones.
func soakFiles(t *testing.T, img fixture.Image) []soakFile {
	t.Helper()
	var out []soakFile
	for _, e := range img.Want {
		rel := string(e.Path)
		if e.Type != "reg" || e.Size == 0 || e.Size > 64<<20 {
			continue
		}
		if strings.HasPrefix(rel, "data/") || strings.HasPrefix(rel, "holes/") {
			out = append(out, soakFile{Rel: rel, Size: e.Size})
		}
	}
	if len(out) == 0 {
		t.Fatalf("image %s has nothing to soak", img.Name)
	}
	return out
}

// probeFile is the file each cycled mount must serve: big enough to span
// several chunks, small enough to read whole every cycle.
func probeFile(t *testing.T, files []soakFile) soakFile {
	t.Helper()
	for _, f := range files {
		if f.Rel == "data/size/00065537" {
			return f
		}
	}
	t.Fatalf("no probe file among the soaked files")
	return soakFile{}
}

// soak is the background read load.
type soak struct {
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	reads atomic.Int64
	bytes atomic.Int64

	mu     sync.Mutex
	failed int
	first  []string
}

func startSoak(m *mount.Mounted, src string, files []soakFile, seed uint64) *soak {
	s := &soak{stop: make(chan struct{}), done: make(chan struct{})}
	var wg sync.WaitGroup
	for i := range nReaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, uint64(i)))
			got, want := make([]byte, maxRead), make([]byte, maxRead)
			for !s.stopped() {
				f := files[rng.IntN(len(files))]
				off := rng.Int64N(f.Size)
				n := min(int64(1+rng.IntN(maxRead)), f.Size-off)
				if err := check(m.Root, src, f.Rel, off, got[:n], want[:n]); err != nil {
					s.fail(err)
					continue
				}
				s.reads.Add(1)
				s.bytes.Add(n)
			}
		}()
	}
	// fileio reads go through the export file, whose page cache would
	// otherwise serve every range after its first read.
	if m.Daemon.Name == "nydus-fileio" {
		export := filepath.Join(filepath.Dir(m.Root), "export")
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !s.stopped() {
				dropCaches(export)
				time.Sleep(250 * time.Millisecond)
			}
		}()
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

// halt asks the readers to stop without waiting for them.
func (s *soak) halt() { s.stopOnce.Do(func() { close(s.stop) }) }

// finish stops the readers, fails t if one is still stuck in a read after
// stopTimeout, and reports every failed or wrong read.
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
	if s.reads.Load() == 0 {
		t.Error("soak completed without a successful verified read")
	}
	if s.failed > 0 {
		t.Errorf("%d reads failed or returned wrong bytes; first: %v", s.failed, s.first)
	}
}

func (s *soak) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed++
	if len(s.first) < 8 {
		s.first = append(s.first, err.Error())
	}
}

// check reads len(got) bytes at off of rel through mnt, after dropping
// their page cache so the daemon serves them, and compares them with src.
func check(mnt, src, rel string, off int64, got, want []byte) error {
	mf, err := os.Open(filepath.Join(mnt, rel))
	if err != nil {
		return err
	}
	defer func() { _ = mf.Close() }()
	_ = unix.Fadvise(int(mf.Fd()), off, int64(len(got)), unix.FADV_DONTNEED)
	if n, err := mf.ReadAt(got, off); n < len(got) {
		return fmt.Errorf("read %s at %d+%d: %v", rel, off, len(got), err)
	}

	sf, err := os.Open(filepath.Join(src, rel))
	if err != nil {
		return err
	}
	defer func() { _ = sf.Close() }()
	if n, err := sf.ReadAt(want, off); n < len(want) {
		return fmt.Errorf("read source %s at %d+%d: %v", rel, off, len(want), err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s at %d+%d: wrong bytes", rel, off, len(got))
	}
	return nil
}

// dropCaches drops the page cache of every file in dir.
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
	if err != nil {
		t.Fatalf("sample daemon %d: %v", pid, err)
	}
	return s
}

// settle samples the daemon until its fds and threads are back within the
// slack of base, or settleTimeout passes, and returns the last sample.
func settle(t *testing.T, pid int, base proc.Sample) proc.Sample {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	for {
		s := sample(t, pid)
		if (s.FDs <= base.FDs+fdSlack && s.Threads <= base.Threads+threadSlack) || time.Now().After(deadline) {
			return s
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// expectNoMounts fails t if anything is mounted at or below dir. mountinfo
// can miss an entry while parallel tests mount and unmount, so the known
// mountpoints are also asked of the kernel directly.
func expectNoMounts(t *testing.T, dir string, known ...string) {
	t.Helper()
	left, err := proc.MountsUnder(dir)
	if err != nil {
		t.Fatalf("list mounts: %v", err)
	}
	for _, p := range known {
		if mount.IsMountpoint(p) {
			left = append(left, p)
		}
	}
	if len(left) > 0 {
		t.Errorf("mounts left behind under %s: %v", dir, left)
	}
}

// expectGone fails t unless every pid has exited within stopTimeout.
func expectGone(t *testing.T, pids []int) {
	t.Helper()
	deadline := time.Now().Add(stopTimeout)
	for {
		var alive []int
		for _, pid := range pids {
			if running(pid) {
				alive = append(alive, pid)
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("processes left behind: %v", alive)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// running reports whether pid exists and is not a zombie.
func running(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(data), ')')
	fields := strings.Fields(string(data[i+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}
