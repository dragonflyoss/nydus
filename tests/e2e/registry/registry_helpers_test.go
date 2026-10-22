package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

type registryImage struct {
	fixture.Image
}

// readWindows releases independent, cold ranges together and validates every
// byte on the test goroutine. A stalled read is bounded by tearing down FUSE.
func readWindows(t *testing.T, m *registryMount, image *registryImage, offsets ...int64) {
	t.Helper()
	type result struct {
		index int
		data  []byte
		err   error
	}
	const rel = "data/size/08392705"
	want, err := os.ReadFile(filepath.Join(image.Source, rel))
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan result, len(offsets))
	for i, offset := range offsets {
		go func(i int, offset int64) {
			<-start
			data, err := readWindow(m.Path(rel), offset)
			results <- result{i, data, err}
		}(i, offset)
	}
	close(start)
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for range offsets {
		select {
		case result := <-results:
			require.NoError(t, result.err)
			offset := offsets[result.index]
			require.Equal(t, want[offset:offset+4096], result.data, "offset %d", offset)
		case <-timer.C:
			m.Unmount()
			t.Fatal("concurrent registry reads exceeded 30s")
		}
	}
}

func readWindow(path string, offset int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data := make([]byte, 4096)
	_, err = f.ReadAt(data, offset)
	return data, err
}

type registryConfig struct {
	mount.Registry
	Prefetch mount.Prefetch
}

type registryMount struct {
	*mount.Mounted
}

func newRegistrySuite(t *testing.T) (*registryImage, *registryProxy, string) {
	t.Helper()
	mount.FUSE{}.Require(t)
	image := &registryImage{fixture.Get(t, "zstd-4k-group-64k")}
	origin := registry.Start(t)
	origin.PushBlobs(t, "e2e/registry", image.Blobs)
	proxy, addr := newRegistryProxy(t, origin.URL)
	return image, proxy, addr
}

func (i *registryImage) config(addr string) registryConfig {
	return registryConfig{
		Registry: mount.Registry{
			Addr: addr, Repository: "e2e/registry",
			HTTP: &mount.HTTP{RequestTimeout: "5s", MaxRetries: mount.Ptr(3)},
		},
		Prefetch: mount.Prefetch{Scope: "none"},
	}
}

func (i *registryImage) mount(t *testing.T, config registryConfig) *registryMount {
	t.Helper()
	m := mount.Mount(t, mount.FUSE{}, i.Image, mount.Options{Config: func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(config.Registry)
		c.Prefetch = &config.Prefetch
		c.Storage.FetchSize = mount.Ptr[int64](0)
	}})
	m.Daemon.WaitFor(t, 10*time.Second, "metrics", func() bool {
		_, err := m.API.Get("/metrics")
		return err == nil
	})
	return &registryMount{m}
}

func (m *registryMount) read(t *testing.T, image *registryImage, rel string) error {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.Root, rel))
	if err != nil {
		return err
	}
	want, err := os.ReadFile(filepath.Join(image.Source, rel))
	require.NoError(t, err)
	require.Equal(t, want, data, "%s differs from source", rel)
	return nil
}

func (m *registryMount) backendReads(t *testing.T, kind, source string) float64 {
	t.Helper()
	return m.API.Metrics(t).Sum("nydus_backend_read_total", `type="`+kind+`"`, `source="`+source+`"`)
}

func (m *registryMount) backendFailures(t *testing.T, kind, source string) float64 {
	t.Helper()
	return m.API.Metrics(t).Sum("nydus_backend_read_failure_total", `type="`+kind+`"`, `source="`+source+`"`)
}

func (m *registryMount) failedReads(t *testing.T, status string) int {
	t.Helper()
	var last int
	require.Eventually(t, func() bool {
		n := strings.Count(m.Daemon.FileLog(), "read failed: unexpected status "+status)
		settled := n > 0 && n == last
		last = n
		return settled
	}, 10*time.Second, 200*time.Millisecond, "no settled read failure for %s", status)
	return last
}

func (m *registryMount) waitLogs(t *testing.T, text string) {
	t.Helper()
	m.Daemon.WaitFor(t, 10*time.Second, text, func() bool {
		return strings.Contains(m.Daemon.FileLog(), text)
	})
}

func waitMetricSettled(t *testing.T, api *mount.API, name string, labels ...string) {
	t.Helper()
	var last float64
	stable := 0
	require.Eventually(t, func() bool {
		value := api.Metrics(t).Sum(name, labels...)
		if value > 0 && value == last {
			stable++
		} else {
			stable = 0
		}
		last = value
		return stable >= 3
	}, 30*time.Second, 300*time.Millisecond, "%s did not settle", name)
}
