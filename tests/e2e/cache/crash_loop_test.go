package cache

import (
	"bytes"
	"math/rand/v2"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"golang.org/x/sys/unix"
)

// TestCrashLoop SIGKILLs and restarts one daemon of a shared cache over and
// over while it fills, as a crash-looping container would. Its peers must
// keep reading the right bytes throughout, and what the loop leaves behind
// must serve the right bytes to a fresh daemon.
func TestCrashLoop(t *testing.T) {
	t.Parallel()
	w := setup(t)
	const (
		repo   = "e2e/cache-crash-loop"
		cycles = 8
	)
	reg := registry.Start(t)
	reg.PushBlobs(t, repo, w.image1.Blobs)
	// Slow fetches of about one group each keep fills in flight whenever
	// the victim dies.
	reg.Faults.Set(registry.Fault{Delay: 50 * time.Millisecond})
	remote := func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(mount.Registry{Addr: reg.URL, Repository: repo})
		c.Storage.FetchSize = mount.Ptr[int64](64 << 10)
	}
	cacheDir := newCache(t)
	peers := mountN(t, 2, w.image1, cacheDir, remote)

	stop := make(chan struct{})
	passes := make([]int, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				for _, name := range []string{"shared.bin", "file1.bin"} {
					got, err := readSum(p.Path(name))
					if err != nil || got != w.want[name] {
						t.Errorf("peer %d pass %d: read %s: sha256 %s, err %v; want sha256 %s", i, passes[i], name, got, err, w.want[name])
						return
					}
				}
				passes[i]++
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}

	seed := uint64(time.Now().UnixNano())
	t.Logf("crash loop seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for range cycles {
		victim := mountOn(t, w.image1, cacheDir, remote, prefetchAll)
		done := make(chan struct{})
		readSeed := rng.Uint64()
		go func() {
			defer close(done)
			victimReads(t, victim.Path("shared.bin"), w.data["shared.bin"], rand.New(rand.NewPCG(readSeed, 1)))
		}()
		// Not a poll: the kill is meant to land at an arbitrary point of
		// the victim's prefetch and reads.
		time.Sleep(100*time.Millisecond + time.Duration(rng.Int64N(int64(500*time.Millisecond))))
		victim.Daemon.Kill()
		<-done
		victim.Unmount()
	}
	close(stop)
	wg.Wait()
	for i, n := range passes {
		if n == 0 {
			t.Errorf("peer %d never completed a pass", i)
		}
	}
	t.Logf("peer passes %v, registry requests %d", passes, len(reg.Faults.Requests()))

	for _, p := range peers {
		p.Unmount()
	}
	fresh := mountOn(t, w.image1, cacheDir)
	oracle.VerifyMount(t, fresh.Root, w.image1.Want, w.image1.Compare())
	t.Logf("fresh daemon filled %.0f groups on top of the crash-looped cache", metric(t, fresh, ondemandFill))
}

// victimReads reads random 64 KiB pieces of path until its daemon dies. The
// reads may fail but must never return wrong bytes.
func victimReads(t *testing.T, path string, data []byte, rng *rand.Rand) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 64<<10)
	pieces := len(data) / len(buf)
	for {
		off := int64(rng.IntN(pieces)) * int64(len(buf))
		_ = unix.Fadvise(int(f.Fd()), off, int64(len(buf)), unix.FADV_DONTNEED)
		n, err := f.ReadAt(buf, off)
		if n > 0 && !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
			t.Errorf("victim read wrong bytes at offset %d", off)
			return
		}
		if err != nil {
			return
		}
	}
}
