package snapshotter

import (
	"fmt"
	"math/rand/v2"
	"os/exec"
	"strings"
	"testing"
	"time"

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
	invocation := n.runningDaemon(t, unit)
	second := n.start(t, pulled)
	assert.Equal(t, invocation, n.runningDaemon(t, unit))
	assert.Equal(t, []string{unit}, n.units(t))
	assertFiles(t, first, img)
	assertFiles(t, second, img)

	first.remove(t)
	n.gc(t)
	assertFiles(t, second, img)
	assert.Never(t, func() bool { return invocationOf(unit) != invocation }, 2*time.Second, 200*time.Millisecond)

	second.remove(t)
	n.gc(t)
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
	killed := n.runningDaemon(t, unit)

	env.Run(t, "systemctl", "kill", "--signal=SIGKILL", unit)
	waitStopped(t, unit, startTimeout)
	c := n.start(t, pulled)
	assertFiles(t, c, img)
	assert.NotEqual(t, killed, n.runningDaemon(t, unit))
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
	assert.Equal(t, "active", show(t, foreign, "ActiveState")["ActiveState"])
}

func TestSnapshotterRestart(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/restart")
	pulled := n.pull(t, img.nydus)
	unit := n.unit(t, pulled)
	first := n.start(t, pulled)
	invocation := n.runningDaemon(t, unit)

	n.restartSnapshotter(t, "snapshotter-restarted", func() { assertFiles(t, first, img) })
	assertFiles(t, first, img)
	second := n.start(t, pulled)
	assertFiles(t, second, img)
	assert.Equal(t, invocation, n.runningDaemon(t, unit))
}

func invocationOf(unit string) string {
	out, err := exec.Command("systemctl", "show", unit, "--property=InvocationID", "--value").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
