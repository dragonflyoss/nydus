package snapshotter

import (
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestSharedDaemon(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/shared")
	pulled := n.pull(t, img.nydus)
	unit := n.unit(t, pulled)

	first := n.start(t, pulled)
	invocation := n.assertRunning(t, unit)
	second := n.start(t, pulled)
	assert.Equal(t, invocation, n.assertRunning(t, unit))
	assert.Equal(t, []string{unit}, n.units(t))
	assertFiles(t, first, img)
	assertFiles(t, second, img)

	first.remove(t)
	n.gc(t)
	assertFiles(t, second, img)
	assert.Never(t, func() bool { return unitProperty(unit, "InvocationID") != invocation }, 2*time.Second, 200*time.Millisecond)

	second.remove(t)
	n.gc(t)
	waitStopped(t, unit, gcTimeout)
	assert.Empty(t, n.units(t))
}

func TestSharedAcrossNamespaces(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	other := n.in(n.namespace + "-other")
	t.Cleanup(func() {
		other.removeContainers(t)
		_ = os.Remove(filepath.Join("/sys/fs/cgroup", other.namespace))
	})

	img := newImage(t, registry.Start(t), "snapshotter/namespaces")
	pulled := n.pull(t, img.nydus, withPrefetch("none"))
	unit := n.unit(t, pulled)
	first := n.start(t, pulled)
	invocation := n.assertRunning(t, unit)
	second := other.start(t, other.pull(t, img.nydus))
	assert.Equal(t, invocation, n.assertRunning(t, unit))
	assert.Equal(t, []string{unit}, n.units(t))
	assert.Equal(t, img.files["/id"], second.sha256sum(t, "/id")["/id"])

	first.remove(t)
	assert.NoError(t, n.client.ImageService().Delete(n.ctx, img.nydus, images.SynchronousDelete()))
	n.gc(t)
	assertFiles(t, second, img)
	assert.Never(t, func() bool { return unitProperty(unit, "InvocationID") != invocation }, 2*time.Second, 200*time.Millisecond)

	second.remove(t)
	other.gc(t)
	waitStopped(t, unit, gcTimeout)
	assert.Empty(t, n.units(t))
}

func TestDaemonKill(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/daemon-kill")
	pulled := n.pull(t, img.nydus)
	unit := n.unit(t, pulled)
	n.start(t, pulled)
	killed := n.assertRunning(t, unit)

	env.Run(t, "systemctl", "kill", "--signal=SIGKILL", unit)
	waitStopped(t, unit, startTimeout)
	c := n.start(t, pulled)
	assertFiles(t, c, img)
	assert.NotEqual(t, killed, n.assertRunning(t, unit))
}

func TestConcurrentDaemons(t *testing.T) {
	t.Parallel()
	count := concurrentDaemons(t)
	n := newNode(t)
	reg := registry.Start(t)
	images := make([]image, count)
	pulled := make([]containerd.Image, count)
	t.Run("pull", func(t *testing.T) {
		for i := range count {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()
				images[i] = newImage(t, reg, fmt.Sprintf("snapshotter/concurrent-%d", i))
				pulled[i] = n.pull(t, images[i].nydus)
			})
		}
	})
	if t.Failed() {
		t.FailNow()
	}

	containers := make([]*container, count)
	errs := make([]error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() {
			containers[i], errs[i] = n.tryStart(pulled[i])
		})
	}
	wg.Wait()
	for _, err := range errs {
		if !assert.NoError(t, err) {
			t.FailNow()
		}
	}

	units := n.units(t)
	assert.Len(t, units, count)
	assertFiles(t, containers[0], images[0])
	assertFiles(t, containers[count-1], images[count-1])
	assert.Contains(t, n.metrics(t), "nydus_snapshotter_daemon_start_failures_total 0")

	n.removeContainers(t)
	n.gc(t)
	for _, unit := range units {
		waitStopped(t, unit, gcTimeout)
	}
}

func concurrentDaemons(t *testing.T) int {
	t.Helper()
	count := env.Int(t, "NYDUS_E2E_DAEMONS", 16)
	if !assert.Positive(t, count) {
		t.FailNow()
	}

	return count
}

func TestDaemonMetrics(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/daemon-metrics")
	pulled := n.pull(t, img.nydus)
	c := n.start(t, pulled)
	assertFiles(t, c, img)

	metrics := n.metrics(t)
	assert.Contains(t, metrics, "nydus_snapshotter_unresponsive_daemons 0")
	assert.Regexp(t, `(?m)^nydus_backend_read_total\{.*chain_id="sha256:`+n.chainID(t, pulled)+`".*image="`+regexp.QuoteMeta(img.nydus)+`"`, metrics)
}

func TestHealth(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	assert.Eventually(t, n.serving, startTimeout, 100*time.Millisecond)
}

func TestConfigReload(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/config-reload")
	pulled := n.pull(t, img.nydus)
	unit := n.unit(t, pulled)
	c := n.start(t, pulled)
	assertFiles(t, c, img)
	invocation := n.assertRunning(t, unit)
	assert.Equal(t, "1073741824", unitProperty(unit, "MemoryHigh"))

	n.memoryHigh = "2GiB"
	n.writeConfig(t)
	assert.Eventually(t, func() bool { return unitProperty(unit, "MemoryHigh") == "2147483648" }, reloadTimeout, 500*time.Millisecond)
	assert.Equal(t, invocation, n.assertRunning(t, unit))
	assertFiles(t, c, img)
}

func TestForeignSlice(t *testing.T) {
	t.Parallel()
	foreignSlice := fmt.Sprintf("system-nydusforeign%08x.slice", rand.Uint32())
	foreign := fmt.Sprintf("nydusd-%064x.service", rand.Uint64())
	env.Run(t, env.LookPath(t, "systemd-run"), "--unit", foreign, "--slice", foreignSlice, "--collect", "sleep", "infinity")
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "stop", foreign, foreignSlice).Run()
	})

	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/foreign-slice")
	pulled := n.pull(t, img.nydus)
	unit := n.unit(t, pulled)
	c := n.start(t, pulled)
	assertFiles(t, c, img)
	assert.Equal(t, []string{unit}, n.units(t))

	c.remove(t)
	n.gc(t)
	waitStopped(t, unit, gcTimeout)
	assert.Equal(t, "active", unitProperty(foreign, "ActiveState"))
}

func TestSnapshotterRestart(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/restart")
	pulled := n.pull(t, img.nydus)
	unit := n.unit(t, pulled)
	first := n.start(t, pulled)
	invocation := n.assertRunning(t, unit)

	n.restartSnapshotter(t, "snapshotter-restarted", func() { assertFiles(t, first, img) })
	assertFiles(t, first, img)
	second := n.start(t, pulled)
	assertFiles(t, second, img)
	assert.Equal(t, invocation, n.assertRunning(t, unit))
}
