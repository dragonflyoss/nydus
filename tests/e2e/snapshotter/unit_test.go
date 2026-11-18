package snapshotter

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

func (n *node) units(t *testing.T) []string {
	t.Helper()
	out := env.Run(t, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--full", "nydusd-*.service")
	var units []string
	for line := range strings.Lines(out) {
		if fields := strings.Fields(line); len(fields) > 0 && unitProperty(fields[0], "Slice") == n.slice {
			units = append(units, fields[0])
		}
	}

	return units
}

func show(t *testing.T, unit string, props ...string) map[string]string {
	t.Helper()
	out := env.Run(t, "systemctl", "show", unit, "--property="+strings.Join(props, ","))
	values := make(map[string]string, len(props))
	for line := range strings.Lines(out) {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[key] = value
		}
	}

	return values
}

func (n *node) assertRunning(t *testing.T, unit string) string {
	t.Helper()
	props := show(t, unit, "ActiveState", "Slice", "InvocationID", "Type")
	assert.Equal(t, "active", props["ActiveState"])
	assert.Equal(t, "notify", props["Type"])
	assert.Equal(t, n.slice, props["Slice"])
	if !assert.NotEmpty(t, props["InvocationID"]) {
		t.FailNow()
	}

	return props["InvocationID"]
}

func waitStopped(t *testing.T, unit string, timeout time.Duration) {
	t.Helper()
	if !assert.Eventually(t, func() bool { return unitProperty(unit, "LoadState") == "not-found" }, timeout, 200*time.Millisecond) {
		t.FailNow()
	}
}

func unitProperty(unit, name string) string {
	out, _ := exec.Command("systemctl", "show", unit, "--property="+name, "--value").Output()
	return strings.TrimSpace(string(out))
}
