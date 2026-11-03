package cache

import (
	"math/rand/v2"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestCrashLoop(t *testing.T) {
	t.Parallel()
	w := setup(t)

	const (
		repo   = "e2e/cache-crash-loop"
		cycles = 8
	)

	reg := registry.Start(t)
	reg.PushBlobs(t, repo, w.lowerImage.Blobs)

	reg.Faults.Set(registry.Fault{Delay: 50 * time.Millisecond})

	remote := func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(mount.RegistryConfig{Addr: reg.URL, Repository: repo})
		c.Storage.FetchSize = mount.Ptr[int64](64 << 10)
	}

	cache := newCache(t)
	readers := cache.mountN(t, 2, w.lowerImage, remote)

	stop := make(chan struct{})
	halt := sync.OnceFunc(func() { close(stop) })
	passes := make([]int, len(readers))
	var wg sync.WaitGroup

	for i, p := range readers {
		wg.Go(func() {
			for {
				for _, name := range []string{"shared.bin", "lower.bin"} {
					got, err := fstest.HashFileCold(p.Path(name))
					if !assert.NoError(t, err) || !assert.Equal(t, w.want[name], got) {
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
		})
	}

	t.Cleanup(func() {
		halt()
		wg.Wait()
	})

	seed := uint64(time.Now().UnixNano())
	t.Logf("crash loop seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))

	for range cycles {
		victim := cache.mount(t, w.lowerImage, remote, prefetchAll)
		done := make(chan struct{})
		readSeed := rng.Uint64()

		go func() {
			defer close(done)
			victimReads(t, victim.Path("shared.bin"), w.data["shared.bin"], rand.New(rand.NewPCG(readSeed, 1)))
		}()

		time.Sleep(100*time.Millisecond + time.Duration(rng.Int64N(int64(500*time.Millisecond))))
		victim.Daemon.Kill()
		<-done
		victim.Unmount()
	}

	halt()
	wg.Wait()
	t.Logf("peer passes %v, registry requests %d", passes, len(reg.Faults.Requests()))

	for _, p := range readers {
		p.Unmount()
	}

	fresh := cache.mount(t, w.lowerImage)
	fstest.VerifyMount(t, fresh.Root, w.lowerImage.Want, w.lowerImage.Compare())
	t.Logf("fresh daemon filled %.0f groups on top of the crash-looped cache", fresh.metric(t, ondemandFill))
}

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
		if n > 0 && !assert.Equal(t, data[off:off+int64(n)], buf[:n]) {
			return
		}
		if err != nil {
			return
		}
	}
}

func TestSurvivesPeerCrash(t *testing.T) {
	t.Parallel()
	w := setup(t)
	const repo = "e2e/cache-peer-crash"
	reg := registry.Start(t)
	reg.PushBlobs(t, repo, w.lowerImage.Blobs)

	remote := func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(mount.RegistryConfig{Addr: reg.URL, Repository: repo})
		c.Storage.FetchSize = mount.Ptr[int64](64 << 10)
	}

	cache := newCache(t)
	survivor := cache.mount(t, w.lowerImage, remote)
	victim := cache.mount(t, w.lowerImage, remote)

	reg.Faults.Set(registry.Fault{Delay: 2 * time.Second})

	go func() { _, _ = fstest.HashFileCold(victim.Path("shared.bin")) }()

	victim.Daemon.WaitFor(t, 30*time.Second, "the victim's fill to reach the registry", func() bool {
		return reg.Faults.Hits() > 0
	})

	victim.Daemon.Kill()
	reg.Faults.Clear()
	t.Logf("victim killed; shared blob all ready at the time: %v", cache.allReady(w.sharedBlob))

	done := make(chan readResult, 1)

	go func() {
		var r readResult
		r.sum, r.err = fstest.HashFileCold(survivor.Path("shared.bin"))
		done <- r
	}()

	select {
	case r := <-done:
		if assert.NoError(t, r.err) {
			assert.Equal(t, w.want["shared.bin"], r.sum)
		}

	case <-time.After(60 * time.Second):
		t.Fatalf("survivor blocked after a peer crashed holding fetch locks")
	}
}
