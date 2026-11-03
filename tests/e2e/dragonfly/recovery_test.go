package dragonfly

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestOutageRecovery(t *testing.T) {
	step := func(name string, fn func(t *testing.T)) {
		t.Helper()
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}

	c := newCluster(t)
	const size = 32 << 20
	img := uniqueImageSize(t, size, "zstd-4k-group-64k")
	origin := startOrigin(t, img)

	m := c.mount(t, img, origin.URL, options{
		fetchSize: mount.Ptr[int64](0), timeout: "2s",
	})

	p := &prober{m: m, src: img.Source}

	for off := int64(0); off < size; off += windowStride {
		p.windows = append(p.windows, window{rel: "data", off: off, n: windowSize})
	}

	d, err := p.readBackend(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Positive(t, d.of(proxyReads)) {
		t.FailNow()
	}

	prefetchImage := uniqueImage(t)
	prefetchOrigin := startOrigin(t, prefetchImage)
	c.stop(t, "seed-client")

	step("SeedPeerFallback", func(t *testing.T) {
		d, err := p.readBackend(t)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		d.expectFallback(t)
	})

	step("PrefetchTransportFailure", func(t *testing.T) {
		failed := c.mount(t, prefetchImage, prefetchOrigin.URL, options{
			prefetch: &mount.PrefetchConfig{Scope: "all", RetryInterval: "1s"},
		})

		failed.Daemon.WaitForLog(t, policyTimeout, "failed to prefetch priority blob")

		failed.assertNoDirectOrigin(t)

		assert.Zero(t, prefetchOrigin.Faults.BlobGets())

		if !assert.Positive(t, failed.API.Metrics(t).Sum("nydus_storage_prefetch_task_failure_total")) {
			t.FailNow()
		}

		assert.Zero(t, failed.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
	})

	step("FallbackRateLimit", func(t *testing.T) {
		rateImage := uniqueImageSize(t, 512<<10, "zstd-4k-group-64k")
		rateOrigin := startOrigin(t, rateImage)

		limited := c.mount(t, rateImage, rateOrigin.URL, options{
			fallbackRateLimit: 1, fetchSize: mount.Ptr[int64](0),
		})

		want, err := os.ReadFile(filepath.Join(rateImage.Source, "data"))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		file, err := os.Open(limited.Path("data"))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		defer func() { assert.NoError(t, file.Close()) }()

		if !assert.NoError(t, unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_RANDOM)) {
			t.FailNow()
		}

		got := make([]byte, len(want))
		start := time.Now()

		for off := 0; off < len(got); off += windowStride {
			_, err := io.ReadFull(file, got[off:min(off+windowStride, len(got))])
			assert.NoError(t, err)
		}

		elapsed := time.Since(start)

		if !assert.True(t, bytes.Equal(want, got)) {
			t.FailNow()
		}

		gets := rateOrigin.Faults.Count(func(r registry.Request) bool { return r.Method == http.MethodGet })
		if !assert.Greater(t, gets, 1) {
			t.FailNow()
		}

		assert.GreaterOrEqual(t, elapsed, time.Duration(gets-1)*800*time.Millisecond)
		assert.Positive(t, limited.API.Metrics(t).Sum("nydus_backend_read_total", `source="fallback"`))
	})

	c.stop(t, "scheduler")

	step("WholeClusterFallback", func(t *testing.T) {
		p.concurrentBatch(t).expectFallback(t)
	})

	step("SchedulerUnavailableAtStartup", func(t *testing.T) {
		started := c.mount(t, prefetchImage, prefetchOrigin.URL, options{})

		d := started.measure(t, func() {
			started.within(t, imageTimeout, "reading the image with the scheduler down", func() {
				assert.NoError(t, started.readData(t))
			})
		})

		d.expectFallback(t)
	})

	step("OriginUnavailable", func(t *testing.T) {
		defer origin.Faults.Clear()

		for _, tc := range []struct {
			name  string
			fault registry.Fault
		}{
			{"503", registry.Fault{Status: http.StatusServiceUnavailable}},
			{"hanging", registry.Fault{Delay: time.Hour}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				origin.Faults.Set(tc.fault)

				for range 2 {
					d, err := p.readBackend(t)
					if !assert.ErrorIs(t, err, unix.EIO) {
						t.FailNow()
					}
					if !assert.Positive(t, d.of(proxyErrors)) {
						t.FailNow()
					}

					assert.Zero(t, d.of(proxyBytes))
				}

				m.Daemon.WaitForLog(t, 5*time.Second, "falling back to the origin")
			})
		}
	})

	c.restore(t)

	step("LiveMountRecovery", func(t *testing.T) {
		start := time.Now()

		for {
			d, err := p.readBackend(t)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			batch := p.concurrentBatch(t)
			if d.of(proxyReads) > 0 && batch.of(proxyReads) > 0 && batch.of(fallbackReads) == 0 {
				if !assert.Zero(t, d.of(proxyErrors)) {
					t.FailNow()
				}

				assert.Zero(t, batch.of(proxyErrors))
				break
			}

			if !assert.Less(t, time.Since(start), recoveryTimeout) {
				t.FailNow()
			}

			time.Sleep(time.Second)
		}
	})

	step("PrefetchRecovery", func(t *testing.T) {
		recovered := c.mount(t, prefetchImage, prefetchOrigin.URL, options{
			prefetch: &mount.PrefetchConfig{Scope: "all", RetryInterval: "1s"},
		})

		recovered.waitPrefetch(t)

		recovered.within(t, imageTimeout, "reading prefetched data after transport recovery", func() {
			assert.NoError(t, recovered.readData(t))
		})

		assert.Zero(t, recovered.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
	})
}

func TestPrefetchRetry(t *testing.T) {
	c := newCluster(t)

	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			img := uniqueImage(t)
			origin := startOrigin(t, img)
			origin.Faults.Set(registry.Fault{Status: status})
			o := policyOptions
			o.prefetch = &mount.PrefetchConfig{Scope: "all", RetryInterval: "1s"}

			m := c.mount(t, img, origin.URL, o)
			if !assert.Eventually(t, func() bool {
				return origin.Faults.Hits() > 0 && strings.Contains(m.Daemon.FileLog(), "dragonfly request failed, retrying in")
			}, policyTimeout, 100*time.Millisecond) {
				t.FailNow()
			}

			if !assert.LessOrEqual(t, origin.Faults.Hits(), 64) {
				t.FailNow()
			}

			origin.Faults.Clear()
			m.waitPrefetch(t)
			before := m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`)

			m.within(t, imageTimeout, "reading prefetched data", func() {
				assert.NoError(t, m.readData(t))
			})

			if !assert.Equal(t, before, m.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`)) {
				t.FailNow()
			}

			assert.Zero(t, before)
			m.assertNoDirectOrigin(t)
		})
	}
}
