package dragonfly

//e2e:serial exercises one outage/recovery cycle of the shared Kind cluster.

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestOutageRecovery(t *testing.T) {
	c := newCluster(t)
	const size = 32 << 20
	img := uniqueImageSize(t, size, "zstd-4k-group-64k")
	origin := startOrigin(t, img)
	m := mountDragonfly(t, c, img, origin.URL, options{
		FetchSize: mount.Ptr[int64](0), Timeout: "2s",
	})
	p := &prober{m: m, src: img.Source}
	for off := int64(0); off < size; off += windowStride {
		p.windows = append(p.windows, window{rel: "data", off: off, n: windowSize})
	}
	d, err := p.readBackend(t)
	require.NoError(t, err)
	require.Positive(t, d.of(proxyReads))

	prefetchImage := uniqueImage(t)
	prefetchOrigin := startOrigin(t, prefetchImage)
	c.stop(t, "dfdaemon")
	require.True(t, t.Run("SeedPeerFallback", func(t *testing.T) {
		d, err := p.readBackend(t)
		require.NoError(t, err)
		expectFallback(t, d, "seed peer down, scheduler still live")
	}))
	require.True(t, t.Run("PrefetchTransportFailure", func(t *testing.T) {
		failed := mountDragonfly(t, c, prefetchImage, prefetchOrigin.URL, options{
			Prefetch: &mount.Prefetch{Scope: "all", RetryInterval: "1s"},
		})
		require.Eventually(t, func() bool {
			return strings.Contains(failed.Daemon.FileLog(), "failed to prefetch priority blob")
		}, policyBound, 100*time.Millisecond)
		assertNoDirectOrigin(t, failed)
		for _, request := range prefetchOrigin.Faults.Requests() {
			require.False(t, request.Method == http.MethodGet && strings.Contains(request.Path, "/blobs/"),
				"prefetch must not read origin while the seed peer is unavailable")
		}
		require.Positive(t, failed.API.Metrics(t).Sum("nydus_storage_prefetch_task_failure_total"))
		require.Zero(t, failed.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
	}))
	require.True(t, t.Run("FallbackRateLimit", func(t *testing.T) {
		rateImage := uniqueImageSize(t, 256<<10, "zstd-4k-group-64k")
		rateOrigin := startOrigin(t, rateImage)
		limited := mountDragonfly(t, c, rateImage, rateOrigin.URL, options{
			FallbackRateLimit: 1, FetchSize: mount.Ptr[int64](0),
		})
		want, err := os.ReadFile(filepath.Join(rateImage.Source, "data"))
		require.NoError(t, err)
		file, err := os.Open(limited.Path("data"))
		require.NoError(t, err)
		defer func() { require.NoError(t, file.Close()) }()
		// A whole-file read or kernel read-ahead may coalesce all groups into one GET.
		require.NoError(t, unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_RANDOM))
		got := make([]byte, len(want))
		start := time.Now()
		for off := 0; off < len(got); off += windowStride {
			_, err := io.ReadFull(file, got[off:min(off+windowStride, len(got))])
			require.NoError(t, err)
		}
		elapsed := time.Since(start)
		require.Equal(t, want, got)
		gets := 0
		for _, request := range rateOrigin.Faults.Requests() {
			if request.Method == http.MethodGet {
				gets++
			}
		}
		require.Greater(t, gets, 1, "the read must need multiple origin GETs")
		require.GreaterOrEqual(t, elapsed, time.Duration(gets-1)*800*time.Millisecond)
		require.Positive(t, limited.API.Metrics(t).Sum("nydus_backend_read_total", `source="fallback"`))
	}))

	c.stop(t, "scheduler")
	require.True(t, t.Run("WholeClusterFallback", func(t *testing.T) {
		expectFallback(t, concurrentBatch(t, p), "concurrent readers with the cluster down")
	}))
	require.True(t, t.Run("OriginUnavailable", func(t *testing.T) {
		defer origin.Faults.Clear()
		for _, step := range []struct {
			name  string
			fault registry.Fault
		}{
			{"503", registry.Fault{Status: http.StatusServiceUnavailable}},
			{"hanging", registry.Fault{Delay: time.Hour}},
		} {
			t.Run(step.name, func(t *testing.T) {
				origin.Faults.Set(step.fault)
				for range 2 {
					d, err := p.readBackend(t)
					expectEIO(t, err, d, "Dragonfly and origin down")
					require.Positive(t, d.of(proxyErrors))
					require.Zero(t, d.of(proxyBytes))
				}
				m.Daemon.WaitFor(t, 5*time.Second, "origin fallback", func() bool {
					return strings.Contains(m.Daemon.FileLog(), "falling back to the origin")
				})
			})
		}
	}))

	c.restore(t)
	require.True(t, t.Run("LiveMountRecovery", func(t *testing.T) {
		start := time.Now()
		for {
			d, err := p.readBackend(t)
			require.NoError(t, err)
			batch := concurrentBatch(t, p)
			if d.of(proxyReads) > 0 && batch.of(proxyReads) > 0 && batch.of(fallbackReads) == 0 {
				require.Zero(t, d.of(proxyErrors))
				require.Zero(t, batch.of(proxyErrors))
				break
			}
			require.Less(t, time.Since(start), recoveryBound,
				"serial and concurrent readers must resume P2P without remounting")
			time.Sleep(time.Second)
		}
	}))
	require.True(t, t.Run("PrefetchRecovery", func(t *testing.T) {
		recovered := mountDragonfly(t, c, prefetchImage, prefetchOrigin.URL, options{
			Prefetch: &mount.Prefetch{Scope: "all", RetryInterval: "1s"},
		})
		waitPrefetch(t, recovered)
		within(t, recovered, imageBound, "reading prefetched data after transport recovery", func() {
			require.NoError(t, readData(t, recovered))
		})
		require.Zero(t, recovered.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
	}))
}
