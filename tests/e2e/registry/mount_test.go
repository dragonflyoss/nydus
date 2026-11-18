package registry

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type registryImage struct {
	fixture.Image
}

type registryConfig struct {
	mount.RegistryConfig
	prefetch mount.PrefetchConfig
}

type registryMount struct {
	*mount.Mounted
}

func newRegistrySuite(t *testing.T) (*registryImage, *registryProxy, string) {
	t.Helper()
	mount.FUSE{}.Require(t)
	image := &registryImage{fixture.Get(t, "zstd-4k-group-64k")}
	origin := registry.Serve(t, image.Image, "e2e/registry")
	proxy, addr := newRegistryProxy(t, origin.Registry.URL)

	return image, proxy, addr
}

func (i *registryImage) config(addr string) registryConfig {
	return registryConfig{
		RegistryConfig: mount.RegistryConfig{
			Addr: addr, Repository: "e2e/registry",
			HTTP: &mount.HTTPConfig{RequestTimeout: "5s", MaxRetries: mount.Ptr(3)},
		},
		prefetch: mount.PrefetchConfig{Scope: "none"},
	}
}

func (i *registryImage) mount(t *testing.T, config registryConfig) *registryMount {
	t.Helper()
	m := mount.Mount(t, mount.FUSE{}, i.Image, mount.Options{Config: func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(config.RegistryConfig)
		c.Prefetch = &config.prefetch
		c.Storage.FetchSize = mount.Ptr[int64](0)
	}})

	m.Daemon.WaitFor(t, 10*time.Second, "metrics", func() bool {
		_, err := m.API.Get("/metrics")
		return err == nil
	})

	return &registryMount{m}
}

func (m *registryMount) readWindows(t *testing.T, image *registryImage, offsets ...int64) {
	t.Helper()
	type result struct {
		index int
		data  []byte
		err   error
	}

	const rel = "data/size/08392705"
	want, err := os.ReadFile(filepath.Join(image.Source, rel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	start := make(chan struct{})
	results := make(chan result, len(offsets))

	for i, offset := range offsets {
		go func() {
			<-start
			data, err := m.readWindow(rel, offset)
			results <- result{i, data, err}
		}()
	}

	close(start)
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for range offsets {
		select {
		case result := <-results:
			if !assert.NoError(t, result.err) {
				t.FailNow()
			}

			offset := offsets[result.index]
			assert.True(t, bytes.Equal(want[offset:offset+4096], result.data))

		case <-timer.C:
			m.Unmount()
			t.Fatal("concurrent registry reads exceeded 30s")
		}
	}
}

func (m *registryMount) readWindow(rel string, offset int64) ([]byte, error) {
	f, err := os.Open(m.Path(rel))
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()
	data := make([]byte, 4096)
	_, err = f.ReadAt(data, offset)

	return data, err
}

func (m *registryMount) read(t *testing.T, image *registryImage, rel string) error {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.Root, rel))
	if err != nil {
		return err
	}

	want, err := os.ReadFile(filepath.Join(image.Source, rel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.True(t, bytes.Equal(want, data))

	return nil
}

func (m *registryMount) expectFailure(t *testing.T, scope string) {
	t.Helper()
	if scope == "all" {
		m.Daemon.WaitForLog(t, 10*time.Second, "failed to prefetch priority blob")
		assert.Zero(t, m.backendReads(t, "ondemand", "http"))
		return
	}

	_, err := m.readWindow("data/size/08392705", 0)
	assert.ErrorIs(t, err, unix.EIO)
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
	if !assert.Eventually(t, func() bool {
		n := strings.Count(m.Daemon.FileLog(), "read failed: unexpected status "+status)
		settled := n > 0 && n == last
		last = n

		return settled
	}, 10*time.Second, 200*time.Millisecond) {
		t.FailNow()
	}

	return last
}

func (m *registryMount) waitMetricSettled(t *testing.T, name string, labels ...string) {
	t.Helper()
	var last float64

	stable := 0
	if !assert.Eventually(t, func() bool {
		body, err := m.API.Get("/metrics")
		if err != nil {
			return false
		}

		value := mount.ParseMetrics(string(body)).Sum(name, labels...)
		if value > 0 && value == last {
			stable++
		} else {
			stable = 0
		}

		last = value

		return stable >= 3
	}, 30*time.Second, 300*time.Millisecond) {
		t.FailNow()
	}
}
